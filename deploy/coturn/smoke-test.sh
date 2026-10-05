#!/usr/bin/env bash
# Smoke-tests the coturn service exactly as docker-compose.yml runs it (the
# image's user, a read-only root, no capabilities, the secret rendered at
# startup), using the turnutils that ship in the image:
#   - it answers STUN;
#   - the shared secret is not in turnserver's argv or environment;
#   - two relayed clients reach each other through it (relay to relay);
#   - it refuses to relay to private addresses.
# Run from deploy/ with a .env in place. Leaves coturn running.
set -euo pipefail

secret=$(sed -n 's/^DOOMMSG_TURN_SECRET=//p' .env)
[ -n "$secret" ] || { echo "DOOMMSG_TURN_SECRET is empty in .env" >&2; exit 1; }
ip=172.30.0.10 # coturn's pinned address, see docker-compose.yml

in_coturn() { timeout 60 docker compose exec -T coturn "$@"; }
fail() {
  echo "$2" | tail -20 >&2
  echo "FAIL: $1" >&2
  exit 1
}

docker compose up -d coturn
for i in $(seq 30); do
  timeout 3 docker compose exec -T coturn turnutils_stunclient "$ip" >/dev/null 2>&1 && break
  [ "$i" = 30 ] && fail "coturn does not answer STUN" "$(docker compose logs coturn)"
  sleep 1
done
echo "ok: answers STUN"

argv=$(in_coturn cat /proc/1/cmdline | tr '\0' ' ')
environ=$(in_coturn cat /proc/1/environ | tr '\0' '\n')
case "$argv$environ" in *"$secret"*) fail "the secret is visible in turnserver's argv or environment" "$argv" ;; esac
mode=$(in_coturn stat -c %a /tmp/turnserver.conf)
[ "$mode" = 600 ] || fail "the rendered config is mode $mode, not 600" ""
echo "ok: secret kept out of argv and environment ($argv)"

out=$(in_coturn turnutils_uclient -y -X -W "$secret" -u smoke -n 20 -m 1 "$ip" 2>&1) || fail "relay to relay failed" "$out"
grep -q "Total lost packets 0 " <<<"$out" || fail "relay to relay lost packets" "$out"
echo "ok: relays between two relayed clients"

# One user per probe: refused allocations linger and count against user-quota.
for peer in 172.30.0.11 10.0.0.1 127.0.0.1 169.254.169.254; do
  out=$(in_coturn turnutils_uclient -X -W "$secret" -u "probe-$peer" -n 3 -m 1 -e "$peer" -r 3480 "$ip" 2>&1) || true
  grep -q "403 (Forbidden IP)" <<<"$out" || fail "relayed to private peer $peer" "$out"
done
echo "ok: refuses private peers"
