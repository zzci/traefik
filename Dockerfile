FROM golang:1.25-alpine AS auth-build

WORKDIR /src
COPY auth/go.mod auth/go.sum ./
RUN go mod download
COPY auth/ .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/auth .

FROM zzci/ubase

# Any traefik release works, including older v2.x (same asset naming).
ARG TRAEFIK_VERSION=v3.7.5
ARG TARGETARCH

WORKDIR /usr/local/bin/

EXPOSE 80 443

RUN \
    ## install htpasswd
    apt-get update && \
    apt-get install -y --no-install-recommends apache2-utils && \
    rm -rf /var/lib/apt/lists/*; \
    ## traefik binary
    wget -qO /tmp/traefik.tar.gz "https://github.com/traefik/traefik/releases/download/${TRAEFIK_VERSION}/traefik_${TRAEFIK_VERSION}_linux_${TARGETARCH}.tar.gz"; \
    tar zxf /tmp/traefik.tar.gz -C /usr/local/bin traefik; \
    chmod +x /usr/local/bin/traefik; \
    ## init plugin dir
    mkdir -p /usr/local/bin/plugins-local/src/; \
    ## oidc-auth
    wget -qO "/tmp/oidc.tar.gz" https://github.com/sevensolutions/traefik-oidc-auth/archive/refs/tags/v0.20.1.tar.gz; \
    mkdir -p /usr/local/bin/plugins-local/src/github.com/sevensolutions/traefik-oidc-auth; \
    tar zxf /tmp/oidc.tar.gz --strip-components=1 -C /usr/local/bin/plugins-local/src/github.com/sevensolutions/traefik-oidc-auth; \
    ## patch: use SessionCookie.Domain for CodeVerifier cookie instead of CallbackURL.Host
    sed -i 's/Domain:   toa.CallbackURL.Host,/Domain:   toa.Config.SessionCookie.Domain,/g' /usr/local/bin/plugins-local/src/github.com/sevensolutions/traefik-oidc-auth/src/main.go; \
    ## patch: disable PKCE double-redirect added in v0.19 (Domain patch above already handles cross-domain callback)
    sed -i 's/if toa.needsDoubleRedirect(req) {/if false \&\& toa.needsDoubleRedirect(req) {/' /usr/local/bin/plugins-local/src/github.com/sevensolutions/traefik-oidc-auth/src/main.go; \
    ## access-auth
    wget -qO "/tmp/access-auth.tar.gz" https://github.com/zzci/access-auth/archive/refs/tags/v1.1.0.tar.gz; \
    mkdir -p /usr/local/bin/plugins-local/src/github.com/zzci/access-auth; \
    tar zxf /tmp/access-auth.tar.gz --strip-components=1 -C /usr/local/bin/plugins-local/src/github.com/zzci/access-auth; \
    ## real-ip
    wget -qO "/tmp/real-ip.tar.gz" https://github.com/Paxxs/traefik-get-real-ip/archive/refs/tags/v1.0.4.tar.gz; \
    mkdir -p /usr/local/bin/plugins-local/src/github.com/Paxxs/traefik-get-real-ip; \
    tar zxf /tmp/real-ip.tar.gz --strip-components=1 -C /usr/local/bin/plugins-local/src/github.com/Paxxs/traefik-get-real-ip; \
    ## clean.
    rm -rf /tmp/*

COPY --from=auth-build /out/auth /usr/local/bin/auth
COPY --chmod=0755 rootfs /

## traefik always runs; auth is a template enabled at runtime via ZSRV_auth=true
RUN mkdir -p /.init/services/run && \
    cp /build/services/traefik.conf /.init/services/run/

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/start.sh"]
