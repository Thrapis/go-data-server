#!/bin/sh
# lego deploy hook: copies the renewed certificate where go-data-server can read it.
# The server notices the new files within a minute and starts using them; no restart needed.
#
# Usage (lego runs it after every successful issue/renewal):
#   lego-deploy-hook.sh <public-ip>
set -eu

ip="${1:?usage: $0 <public-ip>}"
src=/etc/lego/certificates
dst=/etc/go-data-server/tls

install -d -m 755 -o data -g data "$dst"
install -m 644 -o data -g data "$src/$ip.crt" "$dst/cert.pem"
install -m 600 -o data -g data "$src/$ip.key" "$dst/key.pem"
