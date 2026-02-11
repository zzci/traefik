FROM traefik:v3.6.7

WORKDIR /usr/local/bin/

EXPOSE 80 443

RUN \
    ## install htpasswd
    apk add --no-cache openssl ca-certificates apache2-utils; \
    ## init plugin dir
    mkdir -p /usr/local/bin/plugins-local/src/; \
    ## oidc-auth
    wget -qO "/tmp/oidc.tar.gz" https://github.com/sevensolutions/traefik-oidc-auth/archive/refs/tags/v0.18.0.tar.gz; \
    mkdir -p /usr/local/bin/plugins-local/src/oidc; \
    tar zxf /tmp/oidc.tar.gz --strip-components=1 -C /usr/local/bin/plugins-local/src/oidc; \
    ## real-ip
    wget -qO "/tmp/real-ip.tar.gz" https://github.com/Paxxs/traefik-get-real-ip/archive/refs/tags/v1.0.4.tar.gz; \
    mkdir -p /usr/local/bin/plugins-local/src/real-ip; \
    tar zxf /tmp/real-ip.tar.gz --strip-components=1 -C /usr/local/bin/plugins-local/src/real-ip; \
    ## clean.
    rm -rf /tmp/*
