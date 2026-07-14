#!/bin/sh

DOWNLOAD_PATH=/tmp/lightswitch-latest-version
VERSION=latest
ASSET_NAME="lightswitch-static-glibc-$(uname -m)-unknown-linux-gnu"
INSTALLATION_PATH=/usr/sbin/lightswitch

log() {
    echo "↪ $1" >&2
}

# `-L` to follow redirects
log "Downloading lightswitch"
curl --progress-bar -L "https://github.com/javierhonduco/lightswitch/releases/${VERSION}/download/${ASSET_NAME}" --output ${DOWNLOAD_PATH}
chmod +x ${DOWNLOAD_PATH}
log "Installing lightswitch"
sudo mv ${DOWNLOAD_PATH} ${INSTALLATION_PATH}
log "Installed $(lightswitch --version) at ${INSTALLATION_PATH}. Happy profiling!"
