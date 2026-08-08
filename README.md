# traefik

[中文](README_CN.md)

Custom Traefik Docker image with built-in plugins.

## Quick Start

Download the latest release from [Releases](https://github.com/zzci/traefik/releases), then:

```bash
tar xzf traefik-vX.X.X.tar.gz
cd traefik

cp env.example .env
# Edit .env with your settings

# The compose file joins an existing external network; create it once:
docker network create traefik

./aa run
```

## Directory Structure

```
traefik/
├── aa                    # Helper script
├── docker-compose.yml    # Docker Compose config
├── env.example           # Environment variables template
├── auth.yml              # Local auth config template (copy to data/auth.yml)
├── example/
│   ├── middleware.*.yml   # Middleware examples
│   └── service.*.yml     # Service routing examples
├── services/             # Dynamic route configs (auto-watched)
└── data/
    ├── traefik.yml       # Traefik static config
    ├── ssl/              # ACME certificates
    └── logs/             # Access and proxy logs
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ACME_EMAIL` | `admin@example.com` | ACME certificate email |
| `ACME_DISABLE_CNAME` | `true` | Disable CNAME support for LEGO |
| `ACME_DNS_API` | `https://auth.acme-dns.io` | ACME-DNS API endpoint |

### Static Config

Edit `data/traefik.yml` to modify entrypoints, certificate resolvers, plugins, etc.

### Dynamic Routes

Place service configs in `services/` directory. Copy from `example/` and modify as needed.

Add a basic service by creating a file like `services/myapp.yml`:

```yml
http:
  routers:
    myapp:
      entryPoints:
        - https
      rule: Host(`myapp.example.com`)
      service: myapp
      middlewares:
        - pwdauth
      tls: true
  services:
    myapp:
      loadBalancer:
        servers:
          - url: http://myapp:8080
```

### Example Files

**Middlewares:**

| File | Description |
|---|---|
| `middleware.ipauth.yml` | IP allow list |
| `middleware.pwdauth.yml` | Basic Auth |
| `middleware.fwdauth.yml` | Local ForwardAuth login (see [Local Auth](#local-auth-forwardauth)) |
| `middleware.oidc.yml` | OpenID Connect |
| `middleware.cors.yml` | CORS headers |
| `middleware.headers.yml` | Custom request/response headers |
| `middleware.security-headers.yml` | Security headers (HSTS, XSS, etc.) |
| `middleware.ratelimit.yml` | Rate limiting |
| `middleware.compress.yml` | Response compression |
| `middleware.redirect.yml` | WWW redirect |
| `middleware.strip-prefix.yml` | Strip path prefix |

**Services:**

| File | Description |
|---|---|
| `service.https.yml` | HTTPS upstream (skip TLS verify) |
| `service.httptls.yml` | HTTP challenge certificate |
| `service.dnstls.yml` | DNS challenge wildcard certificate (also works for dashboard) |
| `service.notls.yml` | Plain HTTP (no TLS) |
| `service.tcp.yml` | TCP passthrough |
| `service.auth.yml` | Local auth service route |

## Local Auth (ForwardAuth)

A tiny login service (`auth/`) built into the traefik image and supervised
alongside traefik, for protecting routes with a username/password form and
domain-wide SSO — no external IdP, no extra container.

Not started unless enabled. To enable, uncomment the auth block in
`docker-compose.yml`:

```yaml
environment:
  ZSRV_auth: "true"
  AUTH_DOMAIN: example.com                       # cookie covers *.example.com
  AUTH_COOKIE_NAME: _auth                        # optional
  AUTH_USERS: "admin:$$2a$$12$$replace_me:admin" # user:secret[:group|group],...
```

`AUTH_USERS` secrets are bcrypt hashes (`$` escaped as `$$` in compose;
generate with `docker exec -it traefik auth hash`) or plaintext passwords
(convenient, but visible in `docker inspect`; must not contain `:` or `,`).
Optional extras: `AUTH_HOST`, `AUTH_SESSION_TTL`, `AUTH_RATE_LIMIT` (e.g.
`5/5m`). For more control, copy the `auth.yml` template to `data/auth.yml`
as a base config; `AUTH_*` vars override individual fields from the file,
so no config file is ever required.

Then wire up the routes:

```bash
# Route the login page: copy example/service.auth.yml to services/
#    and set your auth host (default auth.<domain>).
# Protect a service: copy example/middleware.fwdauth.yml to services/
#    and add "fwdauth" to that service's middlewares list.
```

Failed logins are rate-limited per IP and per username (default 5 per 5
minutes). Sessions are stateless HMAC cookies scoped to the configured
2nd-level domain; the cookie name is configurable via `cookie_name`.
