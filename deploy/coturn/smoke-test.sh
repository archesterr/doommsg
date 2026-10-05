#!/usr/bin/env bash
# Smoke-tests the coturn service exactly as docker-compose.yml runs it (the
# image's user, a read-only root, no capabilities, the secret rendered at
# startup), using the turnutils that ship in the image:
#   - it answers STUN;
#   - the shared secret is not in turnserver's argv or environment;
#   - two relayed clients reach each other through it (relay to relay);
#   - it refuses to relay to private addresses.
# Run from deploy/ with a .env in place; needs Docker Compose and python3.
# Leaves coturn running.
#
# The secret itself never appears on a command line here either: it is read
# from coturn's rendered config over stdout, and the test client only gets
# TURN REST credentials derived from it that expire within two minutes.
set -euo pipefail

in_coturn() { timeout 60 docker compose exec -T coturn "$@"; }
fail() {
  echo "$2" | tail -20 >&2
  echo "FAIL: $1" >&2
  exit 1
}

# coturn's pinned address, from the compose file itself.
ip=$(docker compose config --format json |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["services"]["coturn"]["networks"]["public"]["ipv4_address"])')
neighbour="${ip%.*}.$((${ip##*.} + 1))"

docker compose up -d coturn
for i in $(seq 30); do
  timeout 3 docker compose exec -T coturn turnutils_stunclient "$ip" >/dev/null 2>&1 && break
  [ "$i" = 30 ] && fail "coturn does not answer STUN on $ip" "$(docker compose logs coturn)"
  sleep 1
done
echo "ok: answers STUN on $ip"

secret=$(in_coturn sed -n 's/^static-auth-secret=//p' /tmp/turnserver.conf)
[ -n "$secret" ] || fail "no static-auth-secret in coturn's rendered config" ""
argv=$(in_coturn cat /proc/1/cmdline | tr '\0' ' ')
environ=$(in_coturn cat /proc/1/environ | tr '\0' '\n')
case "$argv$environ" in *"$secret"*) fail "the secret is visible in turnserver's argv or environment" "$argv" ;; esac
mode=$(in_coturn stat -c %a /tmp/turnserver.conf)
[ "$mode" = 600 ] || fail "the rendered config is mode $mode, not 600" ""
echo "ok: secret kept out of argv and environment ($argv)"

# Prints "<user> <password>": a TURN REST credential for $1, valid for two
# minutes. The secret goes in on stdin.
credential() {
  python3 -c '
import base64, hashlib, hmac, sys, time
secret = sys.stdin.read().rstrip("\n")  # <<< adds a newline
user = "%d:%s" % (time.time() + 120, sys.argv[1])
print(user, base64.b64encode(hmac.new(secret.encode(), user.encode(), hashlib.sha1).digest()).decode())
' "$1" <<<"$secret"
}

read -r user pass < <(credential smoke)
out=$(in_coturn turnutils_uclient -y -X -u "$user" -w "$pass" -n 20 -m 1 "$ip" 2>&1) || fail "relay to relay failed" "$out"
grep -q "Total lost packets 0 " <<<"$out" || fail "relay to relay lost packets" "$out"
echo "ok: relays between two relayed clients"

# One user per probe: refused allocations linger and count against user-quota.
for peer in "$neighbour" 10.0.0.1 127.0.0.1 169.254.169.254; do
  read -r user pass < <(credential "probe-$peer")
  out=$(in_coturn turnutils_uclient -X -u "$user" -w "$pass" -n 3 -m 1 -e "$peer" -r 3480 "$ip" 2>&1) || true
  grep -q "403 (Forbidden IP)" <<<"$out" || fail "relayed to private peer $peer" "$out"
done
echo "ok: refuses private peers"
