#!/bin/sh
set -e

if [ -d /var/log/modsecurity ]; then
  chown -R nginx:nginx /var/log/modsecurity || true
  chmod -R g+rwX /var/log/modsecurity || true
  if [ ! -f /var/log/modsecurity/audit.log ]; then
    touch /var/log/modsecurity/audit.log || true
  fi
  chown nginx:nginx /var/log/modsecurity/audit.log || true
  chmod 664 /var/log/modsecurity/audit.log || true
fi

if [ -d /var/log/nginx ]; then
  chown -R nginx:nginx /var/log/nginx || true
  chmod -R g+rwX /var/log/nginx || true
fi
