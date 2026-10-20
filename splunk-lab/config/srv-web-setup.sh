#!/bin/bash
# SRV-WEB (lab Splunk) : Universal Forwarder vers SPLUNK-01, surveillance du dossier Web avec YARA,
# blocage automatique de la source d'un afflux (fail2ban sur l'alerte Suricata 9000001, 120 s).
set -e
SPLUNK=10.20.40.11
V=10.6.0.5; B=86587d4e3b27
UFH=/opt/splunkforwarder

# 1. L'agent Wazuh n'a pas de gestionnaire dans ce lab
systemctl disable --now wazuh-agent 2>/dev/null || true

# 2. Universal Forwarder (paquet officiel, empreinte verifiee)
cd /tmp
URL=https://download.splunk.com/products/universalforwarder/releases/$V/linux/splunkforwarder-$V-$B-linux-amd64.deb
[ -f uf.deb ] || curl -sSL -o uf.deb "$URL"
curl -sSL -o uf.deb.sha512 "$URL.sha512"
[ "$(grep -oE '[0-9a-f]{128}' uf.deb.sha512 | head -1)" = "$(sha512sum uf.deb | cut -d' ' -f1)" ] || { echo "empreinte UF invalide"; exit 1; }
dpkg -i uf.deb > /dev/null
if [ ! -f $UFH/etc/passwd ]; then
  PW="Uf-$(openssl rand -hex 10)"
  printf '[user_info]\nUSERNAME = admin\nPASSWORD = %s\n' "$PW" > $UFH/etc/system/local/user-seed.conf
  touch /root/ccc-credentials.txt; chmod 600 /root/ccc-credentials.txt
  echo "Splunk Universal Forwarder (local) : admin / $PW" >> /root/ccc-credentials.txt
fi
cat > $UFH/etc/system/local/outputs.conf <<EOF
[tcpout]
defaultGroup = splunk01
[tcpout:splunk01]
server = $SPLUNK:9997
EOF
cat > $UFH/etc/system/local/inputs.conf <<'EOF'
[default]
host = SRV-WEB
[monitor:///var/log/suricata/alerts.json]
index = eq13
sourcetype = suricata:alert
[monitor:///var/log/eq13-fim.log]
index = eq13
sourcetype = eq13:fim
[monitor:///var/log/eq13-yara.log]
index = eq13
sourcetype = eq13:yara
[monitor:///var/log/fail2ban.log]
index = eq13
sourcetype = fail2ban
[monitor:///var/log/auth.log]
index = eq13
sourcetype = linux_secure
EOF
chown -R splunkfwd:splunkfwd $UFH 2>/dev/null || chown -R splunk:splunk $UFH 2>/dev/null || true
$UFH/bin/splunk enable boot-start -systemd-managed 1 --accept-license --answer-yes --no-prompt > /dev/null 2>&1 || true
systemctl restart SplunkForwarder 2>/dev/null || $UFH/bin/splunk restart > /dev/null
# lecture des journaux par le forwarder (le journal d'authentification alimente la detection de connexion privilegiee)
setfacl -m u:splunkfwd:r /var/log/suricata/alerts.json /var/log/fail2ban.log /var/log/auth.log 2>/dev/null || true

# 3. Surveillance du dossier Web + YARA (remplace la surveillance de fichiers de l'agent Wazuh)
apt-get install -y -q inotify-tools fail2ban acl > /dev/null
cat > /usr/local/bin/eq13-fim.sh <<'EOF'
#!/bin/bash
# Ecrit un evenement JSON par fichier cree ou modifie, puis analyse le fichier avec YARA.
RULES=/var/ossec/etc/yara/eq13.yar
inotifywait -m -r -q -e close_write,moved_to,create --format '%e|%w%f' /opt/ccc/www | while IFS='|' read -r ev f; do
  [ -f "$f" ] || continue
  printf '{"time":"%s","host":"SRV-WEB","event":"%s","file":"%s"}\n' "$(date -u +%FT%TZ)" "$ev" "$f" >> /var/log/eq13-fim.log
  /usr/bin/yara "$RULES" "$f" 2>/dev/null | while read -r rule path; do
    printf '{"time":"%s","host":"SRV-WEB","yara_rule":"%s","file":"%s","sha256":"%s"}\n' "$(date -u +%FT%TZ)" "$rule" "$path" "$(sha256sum "$path" | cut -d' ' -f1)" >> /var/log/eq13-yara.log
  done
done
EOF
chmod 755 /usr/local/bin/eq13-fim.sh
touch /var/log/eq13-fim.log /var/log/eq13-yara.log; chmod 644 /var/log/eq13-fim.log /var/log/eq13-yara.log
cat > /etc/systemd/system/eq13-fim.service <<'EOF'
[Unit]
Description=EQ13 surveillance du dossier Web et analyse YARA
After=network.target
[Service]
ExecStart=/usr/local/bin/eq13-fim.sh
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now eq13-fim > /dev/null 2>&1

# 4. Blocage automatique : fail2ban lit les alertes Suricata d'afflux (sid 9000001) et bannit la source 120 s
cat > /etc/fail2ban/filter.d/eq13-ddos.conf <<'EOF'
[Definition]
failregex = "src_ip":"<HOST>".*"signature_id":9000001
datepattern = "timestamp":"%%Y-%%m-%%dT%%H:%%M:%%S
EOF
cat > /etc/fail2ban/jail.d/eq13-ddos.conf <<'EOF'
[eq13-ddos]
enabled  = true
filter   = eq13-ddos
logpath  = /var/log/suricata/alerts.json
backend  = auto
maxretry = 1
findtime = 60
bantime  = 120
ignoreip = 127.0.0.1/8 10.20.40.11
banaction = iptables-allports
chain    = DOCKER-USER
EOF
systemctl enable fail2ban > /dev/null 2>&1; systemctl restart fail2ban
sleep 3
setfacl -m u:splunkfwd:r /var/log/fail2ban.log 2>/dev/null || true
fail2ban-client status eq13-ddos | head -4
systemctl is-active SplunkForwarder eq13-fim fail2ban suricata
