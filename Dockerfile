ARG NIX_BASE_IMAGE=docker.io/nixos/nix:latest
FROM ${NIX_BASE_IMAGE}

# Development image only. The project checkout is bind-mounted at runtime; do
# not COPY source into this image.
ENV LIGHTSWITCH_WORKDIR=/workspace

RUN set -eu; \
    mkdir -p /etc/nix /usr/local/bin "${LIGHTSWITCH_WORKDIR}"; \
    { \
      echo "experimental-features = nix-command flakes"; \
      echo "accept-flake-config = true"; \
    } > /etc/nix/nix.conf; \
    { \
      echo '#!/bin/sh'; \
      echo 'set -u'; \
      echo ''; \
      echo 'workdir="${LIGHTSWITCH_WORKDIR:-/workspace}"'; \
      echo ''; \
      echo 'if [ "$#" -eq 0 ]; then'; \
      echo '  set -- bash'; \
      echo 'fi'; \
      echo ''; \
      echo 'if [ ! -e "$workdir/flake.nix" ]; then'; \
      echo '  echo "lightswitch dev container: mount the repository at $workdir" >&2'; \
      echo '  exit 64'; \
      echo 'fi'; \
      echo ''; \
      echo 'home="${HOME:-/root}"'; \
      echo 'git_config="$home/.gitconfig"'; \
      echo 'safe_directory_line="    directory = $workdir"'; \
      echo 'mkdir -p "$home"'; \
      echo 'if ! grep -Fqx "$safe_directory_line" "$git_config" 2>/dev/null; then'; \
      echo '  {'; \
      echo '    echo "[safe]"'; \
      echo '    echo "    directory = $workdir"'; \
      echo '  } >> "$git_config"'; \
      echo 'fi'; \
      echo ''; \
      echo 'cleanup() {'; \
      echo '  status=$?'; \
      echo '  if [ "${LIGHTSWITCH_CONTAINER_CHOWN:-1}" = "1" ] && [ "$(id -u)" = "0" ] && [ -n "${HOST_UID:-}" ] && [ -n "${HOST_GID:-}" ]; then'; \
      echo '    chown -R "${HOST_UID}:${HOST_GID}" "$workdir" 2>/dev/null || true'; \
      echo '  fi'; \
      echo '  exit "$status"'; \
      echo '}'; \
      echo ''; \
      echo 'trap cleanup EXIT INT TERM'; \
      echo 'cd "$workdir"'; \
      echo 'nix develop --command sh -c '"'"'PATH="/usr/local/bin:$PATH"; exec "$@"'"'"' lightswitch-dev-command "$@"'; \
    } > /usr/local/bin/lightswitch-dev-entrypoint; \
    chmod +x /usr/local/bin/lightswitch-dev-entrypoint; \
    { \
      echo '#!/bin/sh'; \
      echo 'set -eu'; \
      echo ''; \
      echo 'if [ "$(id -u)" != "0" ]; then'; \
      echo '  echo "sudo is only shimmed for the root-run lightswitch dev container" >&2'; \
      echo '  exit 1'; \
      echo 'fi'; \
      echo ''; \
      echo 'while [ "$#" -gt 0 ]; do'; \
      echo '  case "$1" in'; \
      echo '    -E|--preserve-env|--preserve-env=*)'; \
      echo '      shift'; \
      echo '      ;;'; \
      echo '    --)'; \
      echo '      shift'; \
      echo '      break'; \
      echo '      ;;'; \
      echo '    *)'; \
      echo '      break'; \
      echo '      ;;'; \
      echo '  esac'; \
      echo 'done'; \
      echo ''; \
      echo 'if [ "$#" -eq 0 ]; then'; \
      echo '  exit 0'; \
      echo 'fi'; \
      echo ''; \
      echo 'exec "$@"'; \
    } > /usr/local/bin/sudo; \
    chmod +x /usr/local/bin/sudo

WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/lightswitch-dev-entrypoint"]
CMD ["bash"]
