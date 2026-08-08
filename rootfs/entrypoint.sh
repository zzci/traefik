#!/bin/sh
set -e

# Emulates the official traefik image's entrypoint on top of the supervisord
# init (docker `command:` compat):
#   --flags... / traefik --flags...  -> flags become the traefik daemon argv
#                                       (supervisord still runs it, auth too)
#   traefik <subcommand> / version   -> one-shot traefik run, no supervisord
#   anything else (/start.sh, sh)    -> executed verbatim

ARGS_FILE=/run/traefik.args
rm -f "$ARGS_FILE"

daemon_with_args() {
    if [ "$#" -gt 0 ]; then
        : > "$ARGS_FILE"
        for a in "$@"; do
            printf '%s\n' "$a" >> "$ARGS_FILE"
        done
    fi
    exec /start.sh
}

# first arg is a flag (`--api.insecure=true`, ...)
if [ "${1#-}" != "$1" ]; then
    daemon_with_args "$@"
fi

if [ "$1" = "traefik" ]; then
    shift
    if [ "$#" -eq 0 ] || [ "${1#-}" != "$1" ]; then
        daemon_with_args "$@"
    fi
    exec /usr/local/bin/traefik "$@"
fi

# bare traefik subcommand (`version`, `healthcheck`): official-image compat
if /usr/local/bin/traefik "$1" --help >/dev/null 2>&1; then
    exec /usr/local/bin/traefik "$@"
fi

exec "$@"
