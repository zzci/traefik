#!/bin/sh
# Starts traefik like the official image: no config file required.
# - /run/traefik.args exists      -> docker `command:` args, used verbatim
# - /data/traefik.yml exists      -> used as static config
# - ACME_EMAIL set (with file)    -> email flags for the default/dns resolvers
# - none of the above             -> plain `traefik` (configure via TRAEFIK_*
#                                    env vars or a mounted config)
mkdir -p /data/logs

set --

if [ -f /run/traefik.args ]; then
    while IFS= read -r arg; do
        [ -n "$arg" ] && set -- "$@" "$arg"
    done < /run/traefik.args
    exec /usr/local/bin/traefik "$@"
fi

if [ -f /data/traefik.yml ]; then
    set -- --configFile=/data/traefik.yml
    if [ -n "$ACME_EMAIL" ]; then
        set -- "$@" \
            --certificatesresolvers.default.acme.email="$ACME_EMAIL" \
            --certificatesresolvers.dns.acme.email="$ACME_EMAIL"
    fi
fi

exec /usr/local/bin/traefik "$@"
