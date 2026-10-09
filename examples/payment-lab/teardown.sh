#!/bin/sh
# Removes the payment lab: this Compose project's containers, its network and its
# named volumes (docker compose down --volumes). Nothing else is touched.
# Regtest files under runtime/ (certificates, credentials, databases, registry)
# are kept; the credentials stop working with the volumes. Delete them yourself
# when you no longer need them.
set -eu
cd "$(dirname "$0")"
docker compose -f docker-compose.yml -p macwarden-payment-lab down --volumes --remove-orphans
echo "Lab containers, network and volumes removed. Regtest files from lab runs remain under runtime/."
