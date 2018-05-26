#!/usr/bin/env bash

set -e

create-dns \
  -tls_user_crt="/var/lib/puppet/ssl/certs/$(hostname -f).pem" \
  -tls_user_key="/var/lib/puppet/ssl/private_keys/$(hostname -f).pem" << _EOF_
record: {
  domain: "_acme-challenge.${CERTBOT_DOMAIN}.",
  class: "IN", type: "TXT", ttl: 60,
  data: "${CERTBOT_VALIDATION}"
}
_EOF_

# Wait for DNS propagation
sleep 10