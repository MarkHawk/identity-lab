#!/usr/bin/env bash
# Build the evidence packs for the support-training game.
#
#   scripts/evidence-packs.sh              every scenario, and the healthy baseline
#   scripts/evidence-packs.sh <name>...    only these (healthy, or scenario names)
#
# For each: break the scenario, sign in as the user who sees the failure,
# capture what a support engineer would see from each tool, fix it, and turn
# the capture into evidence-packs/packs/<id>.json (tests/packs.py redacts it,
# replaces addresses and IDs, and normalises its times). The answer key goes
# to evidence-packs/answers/<id>.json. Ids are random, kept from the answer
# keys across rebuilds. The lab ends healthy. See evidence-packs/FORMAT.md.
#
# Raw captures live in a 0700 folder outside the repository, with the .env
# secrets packs.py redacts, and are deleted when the script ends.
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
require docker curl jq openssl python3
load_env
# shellcheck source=lib-login.sh
source "$LAB_ROOT/scripts/lib-login.sh"

PACKS="$LAB_ROOT/evidence-packs/packs"
ANSWERS="$LAB_ROOT/evidence-packs/answers"
RESULTS="$LAB_ROOT/test-results"
mkdir -p "$PACKS" "$ANSWERS" "$RESULTS"

WORK="$(umask 077; mktemp -d)"
COMMON="$WORK/common"
SEEN_DIR="$COMMON/seen"
CODES_FILE="$WORK/codes"
mkdir -p "$SEEN_DIR"; : >"$CODES_FILE"
export E2E_TOKENS=1   # e2e.py records the decoded tokens (compose.yaml passes it on)
cleanup() {
  local rc=$?
  "$LAB_ROOT/scripts/fix.sh" --all >"$WORK/fix-all.log" 2>&1 || { tail -n 20 "$WORK/fix-all.log" >&2; rc=1; }
  rm -rf "$WORK"
  exit "$rc"
}
trap cleanup EXIT

# --- what packs.py needs once ---------------------------------------------------------
{
  while read -r v; do
    [[ -n "${!v:-}" ]] && printf '%s\n%s\n' "${!v}" "${!v,,}"
  done < <(sed -n 's/^\([A-Z_]*\(PASSWORD\|SECRET\|SECRET_KEY\)\)=.*/\1/p' "$ENV_FILE")
} >"$COMMON/secrets"
jq -n --arg lab_host "$LAB_HOST" --arg lab_root "$LAB_ROOT" --arg home "$HOME" --arg hostname "$(hostname)" \
  --arg project "$(compose config --format json | jq -r .name)" \
  --argjson host_ips "$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9.]+$' | jq -R . | jq -s .)" \
  '{lab_host: $lab_host, lab_root: $lab_root, home: $home, hostname: $hostname, project: $project, host_ips: $host_ips}' >"$COMMON/env.json"
compose config --format json >"$COMMON/compose.json"

LDAP_USERS=" dave erin frank heidi "
declare -A USER_IDS=()
for u in alice bob carol grace ivan; do USER_IDS[$u]="$(kc_user_id "$u")"; done
CLOCKS=(keycloak saml-sp oidc-rp api radius ldap authenticator)
LOG_SERVICES=(keycloak ldap radius proxy squid saml-sp saml-sp-proxied oidc-rp oidc-rp-proxied oidc-rp-egress oidc-rp-edge api)

# --- recent changes: snapshots before and after the break ---------------------------
# One file per object, one setting per line, comments and blank lines dropped,
# volatile values (timestamps, counters other than failures) left out.
# Stand-ins for a user's or partner's own device are not on the server side, so
# a real change log would never show them: the authenticator ("her phone": its
# clock) and the partner system's client certificate.
cert_summary() { # <pem file> -- subject and validity of each certificate in it
  awk '/-----BEGIN CERTIFICATE-----/{n++} {print > (f "." n)}' f="$1.split" "$1" 2>/dev/null
  local c
  for c in "$1".split.*; do
    [[ -s "$c" ]] && openssl x509 -in "$c" -noout -subject -issuer -startdate -enddate -nameopt RFC2253 2>/dev/null
    rm -f "$c"
  done
}
snapshot() { # <dir>
  local dir="$1" f name c id
  mkdir -p "$dir"
  while read -r f; do
    name="$(sed 's|^\./||; s|/|__|g' <<<"$f")"
    case "$f" in
      *.crt|*.pem) cert_summary "$LAB_ROOT/$f" >"$dir/$name" ;;
      *) grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$LAB_ROOT/$f" >"$dir/$name" || true ;;
    esac
  done < <(cd "$LAB_ROOT" && find .state -type f ! -path '.state/browser/*' ! -path '.state/authenticator/*' \
             ! -path '.state/mtls-client/*' ! -path '*/logs/*' \
             ! -name '*.key' ! -name '*.prev' ! -name '.*' ! -name '*.tmp' | sort)
  kc_api GET "/$REALM" | jq -r 'to_entries[] | select(.value | type != "object" and type != "array")
      | select(.key | test("^(id|notBefore)$") | not) | "\(.key): \(.value)"' >"$dir/keycloak__realm-settings"
  kc_api GET "/$REALM/clients" | jq -r '.[] | select(.clientId | test("^(oidc-rp|https://|idlab-api)")) | .clientId as $c
      | ({enabled, redirectUris, webOrigins, publicClient, standardFlowEnabled} | to_entries[] | "\($c) \(.key): \(.value | tostring)"),
        (.attributes // {} | to_entries[] | select(.key | test("secret|time|timestamp"; "i") | not) | "\($c) attribute \(.key): \(.value)"),
        (.protocolMappers // [] | .[] | "\($c) mapper \(.name): \(.protocolMapper) \(.config | del(.["client.secret"]) | tostring)")' \
    | sort >"$dir/keycloak__clients"
  kc_api GET "/$REALM/components" | jq -r '.[] | .name as $n | .providerId as $p
      | (.config // {} | to_entries[] | select(.key | test("privateKey|certificate|secret|credential|password|keyUse|kid"; "i") | not)
         | "\($n) (\($p)) \(.key): \(.value | tostring)")' | sort >"$dir/keycloak__components"
  kc_api GET "/$REALM/keys" | jq -r '.keys[] | "\(.kid)\t\(.algorithm)\t\(.type)\t\(.status)\t\(.providerPriority)\t\(.certificate // "")"' \
    | while IFS=$'\t' read -r kid alg type status prio cert; do
        printf 'realm key %s %s %s %s priority %s' "$kid" "$alg" "$type" "$status" "$prio"
        [[ -n "$cert" ]] && printf ' certificate notAfter=%s' "$(b64_to_pem "$cert" | openssl x509 -noout -enddate | cut -d= -f2)"
        echo
      done | sort >"$dir/keycloak__keys"
  : >"$dir/keycloak__users"
  # Keycloak's own users only, by IDs looked up once before any window: a
  # username search, or a directory user, makes Keycloak query LDAP.
  for u in alice bob carol grace ivan; do
    id="${USER_IDS[$u]:-}"
    [[ -n "$id" ]] || continue
    kc_api GET "/$REALM/users/$id" | jq -r --arg u "$u" '"\($u) enabled: \(.enabled)", "\($u) requiredActions: \(.requiredActions // [] | join(","))"' >>"$dir/keycloak__users"
    kc_api GET "/$REALM/users/$id/credentials" | jq -r --arg u "$u" '.[] | "\($u) credential \(.type) \(.userLabel // "") \(.credentialData // "")"' >>"$dir/keycloak__users"
    kc_api GET "/$REALM/attack-detection/brute-force/users/$id" 2>/dev/null | jq -r --arg u "$u" '"\($u) brute-force: disabled=\(.disabled) failures=\(.numFailures)"' >>"$dir/keycloak__users" || true
  done
  {
    printf 'challenge-response: %s\n' "$(compose exec -T nas cat /var/lib/nas/challenge 2>/dev/null || echo unset)"
    c="$(compose exec -T nas cat /var/lib/nas/secret 2>/dev/null || true)"
    if [[ "$c" == "$RADIUS_SECRET" ]]; then echo "shared secret: the same as the RADIUS server's client entry (value not shown)"
    else echo "shared secret: differs from the RADIUS server's client entry (value not shown)"; fi
    c=""
  } >"$dir/nas__settings"
}

# --- the tools ----------------------------------------------------------------------
iso() { date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ; }
rel() { # <epoch> <login epoch> -- "N s (D d) before/after the login"
  local d=$(( $1 - $2 )) w=after
  (( d < 0 )) && { d=$(( -d )); w=before; }
  printf '%d s (%s d) %s the login' "$d" "$(awk -v s="$d" 'BEGIN{printf "%.1f", s/86400}')" "$w"
}
cert_lines() { # <label> <pem file> <login epoch>
  local na ns
  openssl x509 -in "$2" -noout -subject -issuer -nameopt RFC2253 2>/dev/null | sed "s|^|$1 |"
  echo "$1 notBefore=$(iso "$(date -u -d "$(openssl x509 -in "$2" -noout -startdate | cut -d= -f2)" +%s)")"
  na="$(openssl x509 -in "$2" -noout -enddate | cut -d= -f2)"; ns="$(date -u -d "$na" +%s)"
  if (( ns <= $3 )); then echo "$1 notAfter=$(iso "$ns") (expired, $(rel "$ns" "$3"))"
  else echo "$1 notAfter=$(iso "$ns") (valid, $(rel "$ns" "$3"))"; fi
  echo "$1 SHA-256 fingerprint $(openssl x509 -in "$2" -noout -fingerprint -sha256 | cut -d= -f2)"
}

tool_clock() { # <dir> <login epoch>
  local svc h c
  {
    if command -v timedatectl >/dev/null; then
      # The host's own time zone is replaced: packs never say where the lab is.
      timedatectl 2>/dev/null | sed -E 's/^( *Time zone:).*/\1 Etc\/UTC (UTC, +0000)/' \
        | awk '/Universal time:/{u=$0; sub(/Universal time:/, "", u)} {a[NR]=$0} END{for(i=1;i<=NR;i++){l=a[i]; if (l ~ /Local time:/) {sub(/Local time:.*/, "Local time:" u, l)}; print l}}' \
        | sed -E 's/ (UTC|GMT|BST)$/ UTC/'
    fi
    for svc in "${CLOCKS[@]}"; do
      h="$(date -u +%s)"
      c="$(compose exec -T "$svc" date -u +%s 2>/dev/null)" || { echo "$svc (not running)"; continue; }
      printf '%s %s host %s offset %+d s\n' "$svc" "$(iso "$c")" "$(iso "$h")" "$(( c - h ))"
    done
  } >"$1/clock.txt"
}

tool_radius() { # <dir> <user>
  local out code=""
  [[ "$2" == heidi ]] && { sleep $(( 31 - $(date +%s) % 30 )); code="$(totp_for heidi new)"; }
  out="$(printf '%s\n%s\n' "$DEMO_PASSWORD" "$code" | compose exec -T nas nas-auth "$2" 2>&1 || true)"
  code=""
  grep -v '^$' <<<"$out" >"$1/radius-test.txt" || true
}

tool_ldap() { # <dir> <user>
  local base=dc=idlab,dc=example
  {
    printf '%s' "$LDAP_BIND_PASSWORD" | compose exec -T ldap ldapsearch -LLL -x -H ldaps://ldap:1636 \
      -D "cn=keycloak-svc,ou=services,$base" -y /dev/stdin -b "ou=people,$base" "(uid=$2)" \
      uid cn sn mail entryUUID createTimestamp modifyTimestamp pwdAccountLockedTime pwdFailureTime 2>&1 || true
    echo "# groups with $2 as a member"
    printf '%s' "$LDAP_BIND_PASSWORD" | compose exec -T ldap ldapsearch -LLL -x -H ldaps://ldap:1636 \
      -D "cn=keycloak-svc,ou=services,$base" -y /dev/stdin -b "$base" "(member=uid=$2,ou=people,$base)" dn 2>&1 || true
  } | grep -v '^$' | grep -vi 'userPassword' >"$1/ldap-user.txt" || true
  [[ -s "$1/ldap-user.txt" ]] || echo "(no entry for uid=$2)" >"$1/ldap-user.txt"
}

tool_token() { # <dir> <app> <login epoch>
  local t="$1/tokens.json" pem="$1/saml-signing.pem"
  {
    # One marker for every flow without a token: packs.py writes the same line for all of them.
    if [[ "$2" == radius || "$2" == mtls ]] || [[ ! -s "$t" ]] || jq -e '.issued == null' "$t" >/dev/null; then echo NO_TOKEN; return; fi
    jq -r --argjson login "$3" '
      def times: if type == "number" then "\(.) (\(todate), \(. - $login | floor) s from the login)" else tostring end;
      .issued | (to_entries[] | select(.key | startswith("oidc")) | .key as $k
        | ($k | sub("oidc_"; "") | sub("_"; " ")) as $name
        | if .value.error then "\($name): \(.value.error)" else
            "\($name) header: \(.value.header | tostring)",
            (.value.claims | to_entries[] | "\($name) claim \(.key): \(if (.key | IN("exp","iat","auth_time","nbf")) then (.value | times) else (.value | tostring) end)")
          end),
        (.saml_response // empty | if .error then "SAML response: \(.error)" else
            "SAML response issuer: \(.issuer)", "SAML response destination: \(.destination)",
            "SAML response status: \(.status)", "SAML response issued: \(.issue_instant)", "SAML response signed: \(.response_signed)",
            (.assertion // empty | "assertion issuer: \(.issuer)", "assertion signed: \(.signed)", "assertion subject NameID: \(.subject_name_id)",
              "assertion subject confirmation: \(.subject_confirmation | tostring)", "assertion conditions: \(.conditions | tostring)",
              "assertion audience: \(.audience)", "assertion authentication: \(.authn | tostring)",
              (.attributes | to_entries[] | "assertion attribute \(.key): \(.value | join(", "))"))
          end)' "$t"
    if jq -e '.issued.saml_response.signing_certificate_b64' "$t" >/dev/null; then
      b64_to_pem "$(jq -r '.issued.saml_response.signing_certificate_b64' "$t")" >"$pem"
      cert_lines "SAML response signing certificate" "$pem" "$3"
    fi
  } >"$1/token.txt"
}

tool_trusted() { # <dir> <login epoch>
  local c i=0 f
  {
    if [[ -s "$IDP_PIN_FILE" ]]; then
      awk '/-----BEGIN CERTIFICATE-----/{n++} {print > (f "." n)}' f="$1/pin" "$IDP_PIN_FILE"
      for f in "$1"/pin.*; do i=$((i + 1)); cert_lines "SAML app's pinned IdP signing certificate $i" "$f" "$2"; done
    else echo "SAML app: no IdP signing certificate pinned"; fi
    i=0
    while read -r c; do
      [[ -n "$c" ]] || continue
      i=$((i + 1)); b64_to_pem "$c" >"$1/meta.$i.pem"
      cert_lines "IdP metadata signing certificate $i" "$1/meta.$i.pem" "$2"
    done < <(idp_metadata_certs 2>/dev/null || true)
    kc_curl "https://$LAB_HOST:$KC_PORT/realms/$REALM/protocol/openid-connect/certs" 2>/dev/null \
      | jq -r '.keys[] | "OIDC JWKS entry: \(.alg), \(.use), \(.kty), id \(.kid)"' || echo "OIDC JWKS: not reachable"
    if [[ -f "$MTLS_CLIENT_DIR/client.crt" ]]; then
      cert_lines "Partner system's client certificate" "$MTLS_CLIENT_DIR/client.crt" "$2"
      echo "Partner system's client certificate, checked against the lab CA: $(mtls_cert_check | cut -f1)"
    else
      echo "Partner system: no client certificate configured"
    fi
  } >"$1/trusted-keys.txt"
}

# --- one pack -------------------------------------------------------------------------
pack_id() { # <name> -- the id this scenario already has, or a new random one
  local f id
  for f in "$ANSWERS"/*.json; do
    [[ -f "$f" ]] && [[ "$(jq -r .scenario "$f")" == "$1" ]] && { jq -r .id "$f"; return; }
  done
  while :; do
    id="case-$(openssl rand -hex 3)"
    [[ -e "$PACKS/$id.json" || -e "$ANSWERS/$id.json" ]] || { echo "$id"; return; }
  done
}

capture() { # <name>  (healthy, or a scenario)
  local name="$1" id dir app user expect since login_at end_at mark rc=0 svc stamp
  if [[ "$name" == healthy ]]; then
    id=healthy app=oidc user=alice expect=""
  else
    load_scenario "$name"
    id="$(pack_id "$name")" app="$SCENARIO_APP" user="${SCENARIO_USER:-alice}" expect="$SCENARIO_EXPECT"
  fi
  dir="$WORK/$id"; mkdir -p "$dir/logs"
  log "capturing ${name} -> $id"
  # break.sh is not used: its state detection probes the lab (status requests,
  # LDAP connection tests, ...), and each scenario's probes would hint at the
  # answer. The window holds the break itself and the failing login; the
  # after-snapshot and the check that it broke come once the window is closed.
  snapshot "$dir/before"
  sleep 1
  since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [[ "$name" != healthy ]]; then
    # In a subshell: a break that calls die then stops only itself, and its
    # message reaches the terminal instead of vanishing with the log.
    ( scenario_break ) >"$dir/break.log" 2>&1 || { tail -n 20 "$dir/break.log" >&2; die "could not break $name"; }
  fi
  snapshot "$dir/after"
  mark="$dir/mark"; : >"$mark"; : >"$SEEN_DIR/tokens.jsonl"
  sleep 1
  login_at="$(date +%s.%N)"
  if [[ -n "$expect" ]]; then login_as "$user" "$app" --expect-error "$expect" >"$dir/login.out" 2>&1 || rc=$?
  else login_as "$user" "$app" --expect ok >"$dir/login.out" 2>&1 || rc=$?; fi
  (( rc == 0 )) || { tail -n 15 "$dir/login.out" >&2; die "$name: the login did not end as expected; no pack"; }
  sleep 2
  # The logs and admin events end here: the tools below make requests of their own.
  local until; until="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  # The browser run's evidence: the newest <app>-<time> files since the mark.
  stamp="$(find "$RESULTS" -maxdepth 1 -newer "$mark" -name "$app-[0-9]*.har" -printf '%T@ %f\n' | sort -n | tail -n 1 | cut -d' ' -f2)"
  if [[ -n "$stamp" ]]; then
    stamp="${stamp%.har}"
    cp "$RESULTS/$stamp.har" "$dir/browser.har"
    cp "$RESULTS/$stamp-cookies.json" "$dir/browser-cookies.json" 2>/dev/null || true
    cp "$RESULTS/$stamp-console.txt" "$dir/browser-console.txt" 2>/dev/null || true
    cp "$RESULTS/$stamp.html" "$dir/page.html" 2>/dev/null || true
  fi
  tail -n 1 "$SEEN_DIR/tokens.jsonl" >"$dir/tokens.json" 2>/dev/null || true
  if [[ "$name" != healthy ]]; then
    # A second clear of the window's end (--until is in whole seconds), so the
    # detection's own probes are never in the pack.
    sleep 1
    local state; state="$(scenario_state)"
    [[ "$state" == broken ]] || die "$name: detected as $state after the break, not broken; no pack"
  fi
  local login_s="${login_at%.*}"
  tool_token "$dir" "$app" "$login_s"
  tool_trusted "$dir" "$login_s"
  tool_clock "$dir" "$login_s"
  tool_radius "$dir" "$([[ "$app" == radius ]] && echo "$user" || echo dave)"
  tool_ldap "$dir" "$([[ "$LDAP_USERS" == *" $user "* ]] && echo "$user" || echo dave)"
  compose ps --format 'table {{.Service}}\t{{.State}}\t{{.Status}}' >"$dir/ps.txt" 2>&1
  end_at="$(date -u -d "$until" +%s)"
  for svc in "${LOG_SERVICES[@]}"; do
    compose logs --no-log-prefix --timestamps --since "$since" --until "$until" "$svc" >"$dir/logs/$svc.log" 2>&1 || true
  done
  kc_api GET "/$REALM/admin-events?max=100" | jq -r --argjson since "$(( $(date -u -d "$since" +%s) * 1000 ))" \
    --argjson until "$(( (end_at + 1) * 1000 ))" '[.[] | select(.time >= $since and .time < $until)] | sort_by(.time)[]
     | "admin event: \(.time) \(.operationType) \(.resourceType) \(.resourcePath) by an administrator from \(.authDetails.ipAddress)"' \
    >"$dir/admin-events.txt" || true
  # IDs and addresses as they are now (a break can recreate a container or add a component).
  local ids=(); mapfile -t ids < <(compose ps -aq)
  docker inspect "${ids[@]}" >"$dir/inspect.json"
  jq -n --argjson users "$(kc_api GET "/$REALM/users?max=200" | jq '[.[] | {id, username}]')" \
        --argjson clients "$(kc_api GET "/$REALM/clients" | jq '[.[] | {id, clientId}]')" \
        --argjson components "$(kc_api GET "/$REALM/components" | jq '[.[] | {id, name}]')" \
        --arg realm "$(kc_api GET "/$REALM" | jq -r .id)" \
        '{users: $users, clients: $clients, components: $components, realm: $realm}' >"$dir/keycloak-ids.json"
  jq -n --arg id "$id" --argjson login_at "$login_at" --argjson end_at "$end_at" --arg app "$app" \
        --arg since "$since" --arg end "$(iso "$end_at")" \
        '{id: $id, login_at: $login_at, end_at: $end_at, app: $app, since: $since, end: $end}' >"$dir/meta.json"
  write_commands "$dir" "$since" "$app" "$user" "$until"
  if [[ "$name" != healthy ]]; then
    "$LAB_ROOT/scripts/fix.sh" "$name" >"$dir/fix.log" 2>&1 || { tail -n 20 "$dir/fix.log" >&2; die "could not fix $name"; }
  fi
  python3 -I "$LAB_ROOT/tests/packs.py" build "$dir" "$COMMON" "$PACKS/$id.json" || die "$name: no pack written"
  [[ "$name" == healthy ]] || write_answer "$id" "$name"
}

write_commands() { # <dir> <since> <app> <user> <until> -- the command each tool shows, without a secret
  local since="$2" ru lu
  ru="$([[ "$3" == radius ]] && echo "$4" || echo dave)"
  lu="$([[ "$LDAP_USERS" == *" $4 "* ]] && echo "$4" || echo dave)"
  jq -n --arg s "$since" --arg u "$5" --arg ru "$ru" --arg lu "$lu" '
    {"user-report": "(the user'"'"'s screen, or the network device'"'"'s output)",
     "compose-ps": "docker compose ps",
     "keycloak-events": "docker compose logs --since \($s) --until \($u) keycloak | grep org.keycloak.events",
     "radius-test": "docker compose exec -T nas nas-auth \($ru)   (radclient; the password on stdin)",
     "clock": "timedatectl; then, in each container, date -u +%s against the host'"'"'s",
     "token": "decoded header and claims of the tokens the app received (never the token or its signature)",
     "trusted-keys": "openssl x509 -noout -subject -issuer -dates -fingerprint -sha256 (the SAML app'"'"'s pinned IdP certificate, the IdP metadata, the JWKS, the partner client certificate)",
     "ldap-user": "ldapsearch -LLL -x -H ldaps://ldap:1636 -D cn=keycloak-svc,ou=services,dc=idlab,dc=example -y <password file> -b ou=people,dc=idlab,dc=example \"(uid=\($lu))\"",
     "recent-changes": "the configuration change record, \($s) to \($u)",
     "browser-har": "the browser'"'"'s HAR export, summarised (cookie values and one-time values removed)",
     "browser-cookies": "the browser'"'"'s cookies after each step (names and attributes only)",
     "browser-console": "the browser'"'"'s developer tools console"}
    + ([ "keycloak","ldap","radius","proxy","squid","saml-sp","saml-sp-proxied","oidc-rp","oidc-rp-proxied","oidc-rp-egress","oidc-rp-edge","api" ]
       | map({key: "logs-\(.)", value: "docker compose logs --since \($s) --until \($u) \(.)"}) | from_entries)' >"$1/commands.json"
}

write_answer() { # <id> <scenario>
  local fixstep
  # A Fix section shared by several scenarios has a bold heading for each part.
  fixstep="$(awk -v h="${SCENARIO_FIX_HEADING:-}" '/^## Fix/{f=1; on=(h==""); next} /^## /{f=0}
    f && h != "" && $0 == "**" h "**"{on=1; next} f && on && /^1\. /{sub(/^1\. /, ""); print; exit}' "$LAB_ROOT/$SCENARIO_RUNBOOK")"
  [[ -n "$fixstep" ]] || die "$2: no first fix step found in $SCENARIO_RUNBOOK (heading: ${SCENARIO_FIX_HEADING:-none})"
  jq -n --arg id "$1" --arg scenario "$2" --arg runbook "$SCENARIO_RUNBOOK" --arg summary "$SCENARIO_SUMMARY" \
        --arg cmd "scripts/fix.sh $2" --arg step "$fixstep" \
        '{id: $id, scenario: $scenario, runbook: $runbook, summary: $summary, fix: {command: $cmd, first_step: $step}}' \
    >"$ANSWERS/$1.json"
}

# --- run ------------------------------------------------------------------------------
start="$(date +%s)"
"$LAB_ROOT/scripts/fix.sh" --all >"$WORK/fix-start.log" 2>&1 || { tail -n 20 "$WORK/fix-start.log" >&2; die "could not start from a healthy lab"; }
names=("$@")
(( ${#names[@]} )) || mapfile -t names < <(echo healthy; scenario_names)
for n in "${names[@]}"; do capture "$n"; done
"$LAB_ROOT/scripts/fix.sh" --all >"$WORK/fix-end.log" 2>&1 || die "could not end healthy"
not_healthy="$("$LAB_ROOT/scripts/status.sh" | grep -cE '^  [a-z0-9-]+ +(broken|unknown) ' || true)"
(( not_healthy == 0 )) || die "$not_healthy scenario(s) are not healthy at the end"
python3 -I "$LAB_ROOT/tests/packs.py" validate "$PACKS" "$ANSWERS"
ok "built ${#names[@]} pack(s) in $(( $(date +%s) - start )) s; every scenario healthy"
