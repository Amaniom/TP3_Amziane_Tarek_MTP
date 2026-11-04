#!/usr/bin/bash
# Detection des echecs SSH repetes et blocage de la source (ipset helios-blacklist)
set -euo pipefail
IFS=$'\n\t'

readonly WINDOW=10min
readonly THRESHOLD=5
readonly IPSET=helios-blacklist
readonly STATE=/var/lib/helios/blocked.txt
readonly LOCK=/run/lock/helios-watch-auth.lock
readonly TAG=helios-watch-auth
readonly WHITELIST=(192.168.56.1 127.0.0.1)

log() { logger -t "$TAG" -p "authpriv.${1}" -- "$2"; }
die() { log err "$1"; exit "${2:-1}"; }

exec 9>"$LOCK"
flock -n 9 || {
    log warning "une autre instance tourne deja"
    exit 2
}

command -v firewall-cmd >/dev/null || die "firewall-cmd absent" 3
firewall-cmd --get-ipsets | grep -qw "$IPSET" || die "ipset $IPSET introuvable" 3
install -d -m 0750 "$(dirname "$STATE")"
touch "$STATE"

is_whitelisted() {
    local ip=$1 w
    for w in "${WHITELIST[@]}"; do
        [[ "$ip" == "$w" ]] && return 0
    done
    return 1
}

# Echecs sur la fenetre glissante : utilisateur inconnu, refus AllowGroups, mauvaise cle/mot de passe
counts=$(journalctl -u sshd.service --since "-${WINDOW}" -o cat --no-pager 2>/dev/null \
    | grep -E 'Invalid user .* from |Failed [a-z-]+ for .* from |User .* from .* not allowed' \
    | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' \
    | awk '{print $2}' | sort | uniq -c || true)

blocked=0
while IFS=' ' read -r n ip; do
    [[ -z "${ip:-}" ]] && continue
    (( n > THRESHOLD )) || continue
    if is_whitelisted "$ip"; then
        log info "${ip} : ${n} echecs mais adresse en liste blanche"
        continue
    fi
    # idempotence : une adresse deja bloquee ne declenche pas de nouvelle alerte
    if firewall-cmd --ipset="$IPSET" --query-entry="$ip" >/dev/null 2>&1; then
        continue
    fi
    firewall-cmd --ipset="$IPSET" --add-entry="$ip" >/dev/null
    grep -qxF "$ip" "$STATE" || echo "$ip" >> "$STATE"
    log warning "BLOCAGE ${ip} : ${n} echecs SSH en ${WINDOW} (seuil ${THRESHOLD})"
    blocked=$((blocked + 1))
done <<< "$counts"

log info "analyse terminee : ${blocked} nouvelle(s) adresse(s) bloquee(s)"
exit 0
