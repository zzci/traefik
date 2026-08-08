package main

import (
	"crypto/subtle"
	"embed"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
)

//go:embed web/*.html
var webFS embed.FS

// dummyHash is compared against when the username is unknown, so failed
// logins take the same time whether or not the user exists.
var dummyHash = mustDummyHash()

func mustDummyHash() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte(randomToken()), bcryptCost)
	if err != nil {
		panic(err)
	}
	return h
}

const (
	bcryptCost     = 12
	reloadInterval = 5 * time.Second
)

type server struct {
	cfg    atomic.Pointer[Config]
	secret []byte
	rl     *rateLimiter
	tmpl   *template.Template
	now    func() time.Time

	// config hot-reload state
	configPath string
	reloadMu   sync.Mutex
	fileStamp  string
}

func newServer(cfg *Config, secret []byte) *server {
	s := &server{
		secret: secret,
		rl:     newRateLimiter(),
		tmpl:   template.Must(template.ParseFS(webFS, "web/*.html")),
		now:    time.Now,
	}
	s.cfg.Store(cfg)
	return s
}

func (s *server) conf() *Config { return s.cfg.Load() }

// --- config hot reload -----------------------------------------------------

// watchConfig reloads the config when the file at path changes (polled every
// reloadInterval, or immediately on SIGHUP). User/password edits take effect
// without restart; listen and data_dir changes still require one.
func (s *server) watchConfig(path string) {
	s.configPath = path
	s.fileStamp = fileStamp(path)
	go func() {
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		tick := time.NewTicker(reloadInterval)
		for {
			select {
			case <-tick.C:
			case <-hup:
				s.reloadMu.Lock()
				s.fileStamp = "\x00force"
				s.reloadMu.Unlock()
			}
			s.reloadIfChanged()
		}
	}()
}

func fileStamp(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d-%d", fi.ModTime().UnixNano(), fi.Size())
}

func (s *server) reloadIfChanged() {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	stamp := fileStamp(s.configPath)
	if stamp == s.fileStamp {
		return
	}
	// remember the stamp either way so a broken file is logged once, not
	// every poll tick
	s.fileStamp = stamp
	cfg, err := loadConfig(s.configPath)
	if err != nil {
		log.Printf("config reload failed, keeping previous config: %v", err)
		return
	}
	old := s.conf()
	if cfg.Listen != old.Listen || cfg.DataDir != old.DataDir {
		log.Printf("config reload: listen/data_dir changes require a restart, ignoring")
		cfg.Listen, cfg.DataDir = old.Listen, old.DataDir
	}
	s.cfg.Store(cfg)
	log.Printf("config reloaded (%d users)", len(cfg.Users))
}

// --- routes ----------------------------------------------------------------

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /verify", s.handleVerify)
	mux.HandleFunc("GET /login", s.handleLoginForm)
	mux.HandleFunc("POST /login", s.handleLoginSubmit)
	mux.HandleFunc("GET /logout", s.handleLogout)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound)
	})
	return mux
}

// --- /verify ---------------------------------------------------------------

func (s *server) handleVerify(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.sessionFrom(r)
	if !ok {
		s.unauthorized(w, r)
		return
	}
	if required := r.URL.Query().Get("groups"); required != "" {
		if !hasAnyGroup(sess.Groups, strings.Split(required, ",")) {
			s.renderMessage(w, http.StatusForbidden, "Access denied",
				"Your account ("+sess.User+") does not have access to this service.", "/logout", "Sign out")
			return
		}
	}
	w.Header().Set("X-Auth-User", sess.User)
	w.Header().Set("X-Auth-Groups", strings.Join(sess.Groups, ","))
	w.WriteHeader(http.StatusOK)
}

func (s *server) unauthorized(w http.ResponseWriter, r *http.Request) {
	if !strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	login := url.URL{Scheme: "https", Host: s.conf().AuthHost, Path: "/login"}
	if rd := forwardedURL(r); rd != "" {
		login.RawQuery = url.Values{"rd": {rd}}.Encode()
	}
	http.Redirect(w, r, login.String(), http.StatusFound)
}

// forwardedURL reconstructs the original request URL from the
// X-Forwarded-* headers traefik sends with the forwardAuth subrequest.
func forwardedURL(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		return ""
	}
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		proto = "https"
	}
	uri := r.Header.Get("X-Forwarded-Uri")
	if uri == "" {
		uri = "/"
	}
	return proto + "://" + host + uri
}

func hasAnyGroup(have, want []string) bool {
	for _, w := range want {
		w = strings.TrimSpace(w)
		if w == "" {
			continue
		}
		for _, h := range have {
			if h == w {
				return true
			}
		}
	}
	return false
}

// --- /login ----------------------------------------------------------------

type loginPage struct {
	CSRF  string
	RD    string
	Error string
}

func (s *server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	rd := r.URL.Query().Get("rd")
	if sess, ok := s.sessionFrom(r); ok {
		if target := s.safeRD(rd); target != "" {
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
		s.renderMessage(w, http.StatusOK, "Signed in",
			"Signed in as "+sess.User+".", "/logout", "Sign out")
		return
	}
	csrf := randomToken()
	http.SetCookie(w, &http.Cookie{
		Name:     s.csrfCookieName(),
		Value:    csrf,
		Path:     "/login",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	s.renderLogin(w, http.StatusOK, loginPage{CSRF: csrf, RD: rd})
}

func (s *server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	csrfCookie, err := r.Cookie(s.csrfCookieName())
	formCSRF := r.PostFormValue("csrf")
	if err != nil || formCSRF == "" ||
		subtle.ConstantTimeCompare([]byte(csrfCookie.Value), []byte(formCSRF)) != 1 {
		s.renderMessage(w, http.StatusForbidden, "Invalid request",
			"The login request could not be validated. Please try again.", "/login", "Back to sign in")
		return
	}

	c := s.conf()
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")
	rd := r.PostFormValue("rd")
	ip := clientIP(r)

	attempts := c.LoginRateLimit.Attempts
	window := time.Duration(c.LoginRateLimit.Window)
	ipKey, userKey := "ip:"+ip, "user:"+username
	if !s.rl.allow(ipKey, attempts, window) || !s.rl.allow(userKey, attempts, window) {
		log.Printf("login rate-limited user=%q ip=%s", username, ip)
		s.renderMessage(w, http.StatusTooManyRequests, "Too many attempts",
			"Too many failed login attempts. Please try again later.", "", "")
		return
	}

	user := c.findUser(username)
	hash := dummyHash
	if user != nil {
		hash = []byte(user.PasswordHash)
	}
	compareErr := bcrypt.CompareHashAndPassword(hash, []byte(password))
	if user == nil || compareErr != nil {
		s.rl.fail(ipKey, window)
		s.rl.fail(userKey, window)
		log.Printf("login failed user=%q ip=%s", username, ip)
		s.renderLogin(w, http.StatusUnauthorized, loginPage{
			CSRF: csrfCookie.Value, RD: rd, Error: "Invalid username or password.",
		})
		return
	}

	s.rl.reset(userKey)
	now := s.now()
	token := signSession(s.secret, session{
		User:   user.Username,
		Groups: user.Groups,
		Iat:    now.Unix(),
		Exp:    now.Add(time.Duration(c.SessionTTL)).Unix(),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     c.CookieName,
		Value:    token,
		Domain:   c.Domain,
		Path:     "/",
		MaxAge:   int(time.Duration(c.SessionTTL).Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	log.Printf("login ok user=%q ip=%s", username, ip)
	target := s.safeRD(rd)
	if target == "" {
		target = "/login"
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	c := s.conf()
	http.SetCookie(w, &http.Cookie{
		Name:     c.CookieName,
		Value:    "",
		Domain:   c.Domain,
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	s.renderMessage(w, http.StatusOK, "Signed out", "You have been signed out.", "/login", "Sign in")
}

// --- helpers ---------------------------------------------------------------

func (s *server) csrfCookieName() string {
	return s.conf().CookieName + "_csrf"
}

func (s *server) sessionFrom(r *http.Request) (session, bool) {
	c, err := r.Cookie(s.conf().CookieName)
	if err != nil {
		return session{}, false
	}
	sess, err := verifySession(s.secret, c.Value, s.now())
	if err != nil {
		return session{}, false
	}
	return sess, true
}

// safeRD returns rd if it points at the configured domain or one of its
// subdomains, otherwise "" (open-redirect guard).
func (s *server) safeRD(rd string) string {
	if rd == "" {
		return ""
	}
	u, err := url.Parse(rd)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return ""
	}
	host := u.Hostname()
	domain := s.conf().Domain
	if host == domain || strings.HasSuffix(host, "."+domain) {
		return u.String()
	}
	return ""
}

// clientIP returns the client address as seen by traefik: the last entry of
// X-Forwarded-For (appended by traefik itself; earlier entries are
// client-controlled), falling back to the socket peer address.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
			return ip
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func (s *server) renderLogin(w http.ResponseWriter, status int, page loginPage) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := s.tmpl.ExecuteTemplate(w, "login.html", page); err != nil {
		log.Printf("render login: %v", err)
	}
}

func (s *server) renderMessage(w http.ResponseWriter, status int, title, text, linkHref, linkText string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	err := s.tmpl.ExecuteTemplate(w, "message.html", map[string]string{
		"Title": title, "Text": text, "LinkHref": linkHref, "LinkText": linkText,
	})
	if err != nil {
		log.Printf("render message: %v", err)
	}
}
