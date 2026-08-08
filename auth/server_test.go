package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newTestServer(t *testing.T) *server {
	t.Helper()
	cfg := &Config{
		Domain:     "example.com",
		CookieName: "_t",
		Users: []User{
			{Username: "alice", PasswordHash: testHash, Groups: []string{"admin"}},
			{Username: "bob", PasswordHash: testHash},
		},
		LoginRateLimit: RateLimitConfig{Attempts: 3, Window: duration(time.Minute)},
	}
	if err := cfg.applyDefaultsAndValidate(); err != nil {
		t.Fatal(err)
	}
	cfg.CookieName = "_t" // keep the short test name over the default
	return newServer(cfg, testSecret)
}

func do(s *server, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	return rec
}

// loginAs runs the full GET+POST login flow and returns the session cookie.
func loginAs(t *testing.T, s *server, username, password, rd, ip string) (*http.Cookie, *httptest.ResponseRecorder) {
	t.Helper()
	rec := do(s, httptest.NewRequest("GET", "/login", nil))
	var csrf *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == s.csrfCookieName() {
			csrf = c
		}
	}
	if csrf == nil {
		t.Fatal("no csrf cookie set on login form")
	}
	form := url.Values{
		"csrf": {csrf.Value}, "rd": {rd},
		"username": {username}, "password": {password},
	}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if ip != "" {
		req.Header.Set("X-Forwarded-For", ip)
	}
	req.AddCookie(csrf)
	rec = do(s, req)
	for _, c := range rec.Result().Cookies() {
		if c.Name == s.cfg.CookieName && c.MaxAge > 0 {
			return c, rec
		}
	}
	return nil, rec
}

func verifyReq(cookie *http.Cookie, query, accept string) *http.Request {
	req := httptest.NewRequest("GET", "/verify"+query, nil)
	req.Header.Set("Accept", accept)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	req.Header.Set("X-Forwarded-Uri", "/dash?x=1")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	return req
}

func TestVerifyNoCookieBrowserRedirects(t *testing.T) {
	s := newTestServer(t)
	rec := do(s, verifyReq(nil, "", "text/html,application/xhtml+xml"))
	if rec.Code != http.StatusFound {
		t.Fatalf("status: got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	want := "https://auth.example.com/login?rd=" + url.QueryEscape("https://app.example.com/dash?x=1")
	if loc != want {
		t.Fatalf("location:\n got %s\nwant %s", loc, want)
	}
}

func TestVerifyNoCookieAPIGets401(t *testing.T) {
	s := newTestServer(t)
	rec := do(s, verifyReq(nil, "", "application/json"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d", rec.Code)
	}
}

func TestLoginFlowAndVerify(t *testing.T) {
	s := newTestServer(t)
	cookie, rec := loginAs(t, s, "alice", "secret", "https://app.example.com/dash", "")
	if cookie == nil {
		t.Fatalf("no session cookie; status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "https://app.example.com/dash" {
		t.Fatalf("redirect: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if cookie.Domain != "example.com" || !cookie.HttpOnly || !cookie.Secure {
		t.Fatalf("cookie attrs: %+v", cookie)
	}

	vrec := do(s, verifyReq(cookie, "", "text/html"))
	if vrec.Code != http.StatusOK {
		t.Fatalf("verify: got %d", vrec.Code)
	}
	if vrec.Header().Get("X-Auth-User") != "alice" || vrec.Header().Get("X-Auth-Groups") != "admin" {
		t.Fatalf("headers: user=%q groups=%q",
			vrec.Header().Get("X-Auth-User"), vrec.Header().Get("X-Auth-Groups"))
	}
}

func TestVerifyGroupAuthorization(t *testing.T) {
	s := newTestServer(t)
	alice, _ := loginAs(t, s, "alice", "secret", "", "")
	bob, _ := loginAs(t, s, "bob", "secret", "", "")

	if rec := do(s, verifyReq(alice, "?groups=admin,ops", "text/html")); rec.Code != http.StatusOK {
		t.Fatalf("alice with admin: got %d", rec.Code)
	}
	if rec := do(s, verifyReq(bob, "?groups=admin", "text/html")); rec.Code != http.StatusForbidden {
		t.Fatalf("bob without admin: got %d", rec.Code)
	}
}

func TestVerifyExpiredSession(t *testing.T) {
	s := newTestServer(t)
	now := time.Now()
	token := signSession(testSecret, session{
		User: "alice", Iat: now.Add(-2 * time.Hour).Unix(), Exp: now.Add(-time.Hour).Unix(),
	})
	rec := do(s, verifyReq(&http.Cookie{Name: "_t", Value: token}, "", "text/html"))
	if rec.Code != http.StatusFound {
		t.Fatalf("expired session: got %d, want redirect", rec.Code)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	s := newTestServer(t)
	cookie, rec := loginAs(t, s, "alice", "wrong", "", "")
	if cookie != nil {
		t.Fatal("session cookie set on failed login")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Invalid username or password") {
		t.Fatal("error message not rendered")
	}
}

func TestLoginUnknownUserSameResponse(t *testing.T) {
	s := newTestServer(t)
	_, rec := loginAs(t, s, "nobody", "whatever", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Invalid username or password") {
		t.Fatal("unknown user must get the same error as wrong password")
	}
}

func TestLoginCSRFMismatch(t *testing.T) {
	s := newTestServer(t)
	form := url.Values{"csrf": {"forged"}, "username": {"alice"}, "password": {"secret"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: s.csrfCookieName(), Value: "different"})
	if rec := do(s, req); rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d", rec.Code)
	}
}

func TestLoginRateLimitPerIP(t *testing.T) {
	s := newTestServer(t)
	for i := 0; i < 3; i++ {
		if _, rec := loginAs(t, s, "alice", "wrong", "", "9.9.9.9"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d", i, rec.Code)
		}
	}
	// 4th attempt from the same IP is blocked even with correct credentials.
	if _, rec := loginAs(t, s, "alice", "secret", "", "9.9.9.9"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", rec.Code)
	}
	// A different IP hitting the same username is also blocked (user bucket).
	if _, rec := loginAs(t, s, "alice", "secret", "", "8.8.8.8"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("user bucket: want 429, got %d", rec.Code)
	}
	// A different user from a different IP is unaffected.
	if cookie, rec := loginAs(t, s, "bob", "secret", "", "7.7.7.7"); cookie == nil {
		t.Fatalf("bob should be unaffected, got %d", rec.Code)
	}
}

func TestLoginSuccessResetsUserBucket(t *testing.T) {
	s := newTestServer(t)
	// Two failures, then success: user bucket resets.
	loginAs(t, s, "alice", "wrong", "", "1.1.1.1")
	loginAs(t, s, "alice", "wrong", "", "2.2.2.2")
	if cookie, rec := loginAs(t, s, "alice", "secret", "", "3.3.3.3"); cookie == nil {
		t.Fatalf("login should succeed, got %d", rec.Code)
	}
	if !s.rl.allow("user:alice") {
		t.Fatal("user bucket should be reset after success")
	}
}

func TestOpenRedirectGuard(t *testing.T) {
	s := newTestServer(t)
	cases := map[string]string{
		"https://app.example.com/x":     "https://app.example.com/x",
		"https://example.com/":          "https://example.com/",
		"https://evil.com/":             "/login",
		"https://evilexample.com/":      "/login",
		"https://example.com.evil.com/": "/login",
		"javascript:alert(1)":           "/login",
		"//evil.com/":                   "/login",
		"https://u:p@app.example.com/":  "/login",
	}
	for rd, want := range cases {
		cookie, rec := loginAs(t, s, "alice", "secret", rd, "")
		if cookie == nil {
			t.Fatalf("rd=%q: login failed (%d)", rd, rec.Code)
		}
		if got := rec.Header().Get("Location"); got != want {
			t.Errorf("rd=%q: redirect got %q, want %q", rd, got, want)
		}
		do(s, httptest.NewRequest("GET", "/logout", nil))
	}
}

func TestLogoutClearsCookie(t *testing.T) {
	s := newTestServer(t)
	rec := do(s, httptest.NewRequest("GET", "/logout", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d", rec.Code)
	}
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "_t" && c.MaxAge < 0 && c.Domain == "example.com" {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("session cookie not cleared")
	}
}

func TestLoginPageShowsSignedInState(t *testing.T) {
	s := newTestServer(t)
	cookie, _ := loginAs(t, s, "alice", "secret", "", "")
	req := httptest.NewRequest("GET", "/login", nil)
	req.AddCookie(cookie)
	rec := do(s, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "alice") {
		t.Fatalf("signed-in page: %d %s", rec.Code, rec.Body.String())
	}
}

func TestClientIPUsesLastXFFEntry(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 1.2.3.4")
	if ip := clientIP(req); ip != "1.2.3.4" {
		t.Fatalf("got %q, want last entry", ip)
	}
	req.Header.Del("X-Forwarded-For")
	req.RemoteAddr = "5.5.5.5:1234"
	if ip := clientIP(req); ip != "5.5.5.5" {
		t.Fatalf("got %q", ip)
	}
}

func TestHealth(t *testing.T) {
	s := newTestServer(t)
	if rec := do(s, httptest.NewRequest("GET", "/health", nil)); rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestForwardedURLDefaults(t *testing.T) {
	req := httptest.NewRequest("GET", "/verify", nil)
	if got := forwardedURL(req); got != "" {
		t.Fatalf("no host: got %q", got)
	}
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	if got := forwardedURL(req); got != "https://app.example.com/" {
		t.Fatalf("defaults: got %q", got)
	}
}

func TestLoginFormRedirectsWhenAlreadySignedIn(t *testing.T) {
	s := newTestServer(t)
	cookie, _ := loginAs(t, s, "alice", "secret", "", "")
	req := httptest.NewRequest("GET", "/login?rd="+url.QueryEscape("https://app.example.com/x"), nil)
	req.AddCookie(cookie)
	rec := do(s, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://app.example.com/x" {
		t.Fatalf("got %d %s", rec.Code, rec.Header().Get("Location"))
	}
}
