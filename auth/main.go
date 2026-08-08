package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
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

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  auth serve -c config.yml   start the ForwardAuth server
  auth hash                  bcrypt a password read from stdin`)
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("c", "config.yml", "path to config file")
	fs.Parse(args)

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	secret, err := loadSecret(cfg.DataDir)
	if err != nil {
		log.Fatal(err)
	}
	s := newServer(cfg, secret)
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           s.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("listening on %s (domain=%s cookie=%s)", cfg.Listen, cfg.Domain, cfg.CookieName)
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
