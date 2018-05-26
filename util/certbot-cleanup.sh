#!/usr/bin/env bash

set -e

create-dns -method=remove \
  -tls_user_crt="/var/lib/puppet/ssl/certs/$(hostname -f).pem" \
  -tls_user_key="/var/lib/puppet/ssl/private_keys/$(hostname -f).pem" << _EOF_
record: {
  domain: "_acme-challenge.${CERTBOT_DOMAIN}.",
  type: "TXT"
}
_EOF_