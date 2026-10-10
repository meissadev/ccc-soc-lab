#!/bin/bash
# EQ13 : regroupement des alertes Suricata repetitives (SRV-WEB). Additif et reversible (sauvegarde dans /root/eq13-backup-suricata).
set -e
B=/root/eq13-backup-suricata
mkdir -p $B
[ -f $B/threshold.config ] || cp -p /etc/suricata/threshold.config $B/threshold.config
[ -f $B/eq13-local.rules ] || cp -p /var/lib/suricata/rules/eq13-local.rules $B/eq13-local.rules

# 1. Une alerte par minute, par source et par signature, pour les familles bavardes d'Emerging Threats
python3 - <<'PY'
import re
fams = ("HUNTING", "INFO", "POLICY", "SCAN", "USER_AGENTS")
out = []
for l in open("/var/lib/suricata/rules/suricata.rules", encoding="utf-8", errors="ignore"):
    if not l.startswith("alert"):
        continue
    m = re.search(r'msg:"ET (\w+) ', l)
    s = re.search(r'[; ]sid:(\d+);', l)
    if m and s and m.group(1) in fams and "threshold:" not in l and "detection_filter" not in l:
        out.append("threshold gen_id 1, sig_id %s, type limit, track by_src, count 1, seconds 60" % s.group(1))
base = open("/root/eq13-backup-suricata/threshold.config").read().rstrip()
open("/etc/suricata/threshold.config", "w").write(base + "\n\n# EQ13 : limite les alertes repetitives (1 par minute, par source et par signature)\n" + "\n".join(out) + "\n")
print("entrees de limitation :", len(out))
PY

# 2. Regle DDoS de la banque : une seule alerte par fenetre de 10 s et par source (au lieu d'une tous les 50 requetes)
sed -i 's/threshold: type threshold, track by_src, count 50, seconds 10;/threshold: type both, track by_src, count 50, seconds 10;/; s/sid:9000001; rev:1;/sid:9000001; rev:2;/' /var/lib/suricata/rules/eq13-local.rules
grep -o 'threshold:[^;]*;\|rev:[0-9]*' /var/lib/suricata/rules/eq13-local.rules

# 3. Test de la configuration, puis redemarrage (on conserve le proprietaire des journaux)
declare -A OWN
for f in /var/log/suricata/*.json /var/log/suricata/*.log; do OWN[$f]=$(stat -c %U:%G "$f"); done
suricata -T -c /etc/suricata/suricata.yaml > /tmp/suri-test.log 2>&1 && echo "TEST OK" || { echo "TEST KO"; tail -20 /tmp/suri-test.log;
  cp -p $B/threshold.config /etc/suricata/threshold.config; cp -p $B/eq13-local.rules /var/lib/suricata/rules/eq13-local.rules; exit 1; }
for f in "${!OWN[@]}"; do [ -f "$f" ] && chown "${OWN[$f]}" "$f"; done
systemctl restart suricata
for i in $(seq 1 30); do sleep 5; grep -q "Engine started" /var/log/suricata/suricata.log 2>/dev/null && tail -50 /var/log/suricata/suricata.log | grep -q "Engine started" && break; done
systemctl is-active suricata
grep -i -E "threshold|rules successfully loaded|signatures processed" /var/log/suricata/suricata.log | tail -4
ls -la /var/log/suricata/ | grep -E "alerts|eve"
