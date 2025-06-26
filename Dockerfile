FROM traefik:v3.4.1

WORKDIR /usr/local/bin/

EXPOSE 80 443

RUN \
    ## install htpasswd
    apk add --no-cache openssl ca-certificates apache2-utils; \
    ## init plugin dir
    mkdir -p /usr/local/bin/plugins-local/src/github.com/; \
    ## traefik-auth
    wget -qO "/tmp/traefik-auth.tar.gz" https://github.com/traefik-plugins/traefik-jwt-plugin/archive/refs/tags/v0.8.2.tar.gz; \
    mkdir -p /usr/local/bin/plugins-local/src/github.com/traefik-plugins/traefik-jwt-plugin ; \
    tar zxf /tmp/traefik-auth.tar.gz --strip-components=1 -C /usr/local/bin/plugins-local/src/github.com/traefik-plugins/traefik-jwt-plugin; \
    ## fail2ban
    wget -qO "/tmp/fail2ban.tar.gz" https://github.com/tomMoulard/fail2ban/archive/refs/tags/v0.8.1.tar.gz; \
    mkdir -p /usr/local/bin/plugins-local/src/github.com/tomMoulard/fail2ban; \
    tar zxf /tmp/fail2ban.tar.gz --strip-components=1 -C /usr/local/bin/plugins-local/src/github.com/tomMoulard/fail2ban; \
    ## traefik-real-ip
    wget -qO "/tmp/traefik-real-ip.tar.gz" https://github.com/zzci/traefik-real-ip/archive/refs/tags/v1.0.0.tar.gz; \
    mkdir -p /usr/local/bin/plugins-local/src/github.com/zzci/traefik-real-ip; \
    tar zxf /tmp/traefik-real-ip.tar.gz --strip-components=1 -C /usr/local/bin/plugins-local/src/github.com/zzci/traefik-real-ip; \
    ## clean.
    rm -rf /tmp/*
