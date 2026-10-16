#!/bin/bash
# SPLUNK-01 : installe Splunk Enterprise 10.6.0.5 (licence d'essai), crée l'index eq13,
# active la réception des forwarders (9997) et le HTTP Event Collector (8088).
# Idempotent : relançable sans dcommage. Secrets générés : /root/ccc-credentials.txt (root, 600).
set -euo pipefail
V=10.6.0.5; B=86587d4e3b27
DEB=/tmp/splunk.deb
URL=https://download.splunk.com/products/splunk/releases/$V/linux/splunk-$V-$B-linux-amd64.deb
SPL=/opt/splunk
CRED=/root/ccc-credentials.txt

# 1. Téléchargement + vérification d'empreinte
if [ ! -x $SPL/bin/splunk ]; then
  [ -f $DEB ] || curl -sSL -o $DEB "$URL"
  curl -sSL -o $DEB.sha512 "$URL.sha512"
  [ "$(grep -oE '[0-9a-f]{128}' $DEB.sha512 | head -1)" = "$(sha512sum $DEB | cut -d' ' -f1)" ] || { echo "empreinte Splunk invalide"; exit 1; }
  dpkg -i $DEB >/dev/null
fi

# Utilisateur de service splunk (l'app eq13 fait chown splunk:splunk)
id splunk >/dev/null 2>&1 || useradd -r -m -d /opt/splunk -s /bin/bash splunk

# 2. Mot de passe admin (généré sur la machine, jamais en clair hors de cette machine)
touch $CRED; chmod 600 $CRED
if ! grep -q "^Splunk Enterprise" $CRED 2>/dev/null; then
  PW="Spl-$(openssl rand -hex 12)!Aa1"
  cat > $SPL/etc/system/local/user-seed.conf <<EOF
[user_info]
USERNAME = admin
PASSWORD = $PW
EOF
  echo "Splunk Enterprise (https://localhost:8000) : admin / $PW" >> $CRED
fi
chown -R splunk:splunk $SPL

# 3. Premier démarrage + boot-start systemd (service Splunkd), licence d'essai acceptée
if [ ! -f $SPL/etc/splunk-launch.conf ] || ! systemctl list-unit-files | grep -q '^Splunkd'; then
  $SPL/bin/splunk enable boot-start -user splunk -systemd-managed 1 --accept-license --answer-yes --no-prompt >/dev/null
fi
systemctl start Splunkd
for i in $(seq 1 30); do sleep 5; curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8089/services/server/info | grep -q 401 && break; done

ADMIN="-auth admin:$(grep '^Splunk Enterprise' $CRED | sed -E 's/.*admin \/ //')"

# 4. Index eq13
$SPL/bin/splunk list index $ADMIN 2>/dev/null | grep -qw eq13 || \
  $SPL/bin/splunk add index eq13 $ADMIN >/dev/null

# 5. Réception des Universal Forwarders (9997)
$SPL/bin/splunk display listen 9997 $ADMIN 2>/dev/null | grep -qi "Receiving" || \
  $SPL/bin/splunk enable listen 9997 $ADMIN >/dev/null

# 6. HTTP Event Collector (8088) + un token pour l'index eq13
$SPL/bin/splunk http-event-collector enable $ADMIN >/dev/null 2>&1 || true
if ! $SPL/bin/splunk http-event-collector list $ADMIN 2>/dev/null | grep -q "eq13-hec"; then
  TOK=$($SPL/bin/splunk http-event-collector create eq13-hec -index eq13 -uri https://127.0.0.1:8089 $ADMIN 2>/dev/null | grep -i token | grep -oE '[0-9a-f-]{36}' | head -1 || true)
  [ -n "$TOK" ] && echo "Splunk HEC token (eq13-hec, index eq13) : $TOK" >> $CRED
fi

systemctl restart Splunkd
for i in $(seq 1 30); do sleep 5; curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8089/services/server/info | grep -q 401 && break; done

echo "=== État Splunk ==="
systemctl is-active Splunkd
$SPL/bin/splunk version
$SPL/bin/splunk list index $ADMIN 2>/dev/null | grep -w eq13 && echo "index eq13 OK"
$SPL/bin/splunk display listen 9997 $ADMIN 2>/dev/null
echo "Identifiants dans $CRED :"; grep -c . $CRED
