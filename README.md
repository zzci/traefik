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

./aa run
```

## Directory Structure

```
traefik/
├── aa                    # Helper script
├── docker-compose.yml    # Docker Compose config
├── env.example           # Environment variables template
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
| `TRAEFIK_NETWORK` | `traefik` | Docker network name |
| `TRAEFIK_SUBNET` | `172.18.0.0/16` | Docker network subnet |
| `TRAEFIK_IPV4` | `172.18.0.2` | Traefik container IP |

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
