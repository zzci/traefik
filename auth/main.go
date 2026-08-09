package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "hash":
		cmdHash()
	default:
		usage()
		os.Exit(2)
	}
}

const defaultConfigPath = "/data/auth.yml"

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  auth serve [-c config.yml]   start the ForwardAuth server
                               (config path: -c > $AUTH_CONFIG > `+defaultConfigPath+`)
  auth hash                    bcrypt a password read from stdin`)
}

// resolveConfigPath picks the config file path: explicit -c flag first,
// then the AUTH_CONFIG environment variable, then the built-in default.
func resolveConfigPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv("AUTH_CONFIG"); env != "" {
		return env
	}
	return defaultConfigPath
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("c", "", "path to config file (default $AUTH_CONFIG or "+defaultConfigPath+")")
	fs.Parse(args)
	path := resolveConfigPath(*configPath)

	initLogger()
	cfg, err := loadConfig(path)
	if err != nil {
		log.Fatal(err)
	}
	applyLogLevel(cfg.LogLevel)
	secret, err := loadSecret(cfg.DataDir)
	if err != nil {
		log.Fatal(err)
	}
	s := newServer(cfg, secret)
	s.watchConfig(path)
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           s.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	slog.Info("listening", "addr", cfg.Listen, "domain", cfg.Domain,
		"cookie", cfg.CookieName, "config", path, "log_level", cfg.LogLevel)
	log.Fatal(srv.ListenAndServe())
}

func cmdHash() {
	fmt.Fprint(os.Stderr, "Password: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		log.Fatal(err)
	}
	password := strings.TrimRight(line, "\r\n")
	if password == "" {
		log.Fatal("empty password")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(hash))
}
