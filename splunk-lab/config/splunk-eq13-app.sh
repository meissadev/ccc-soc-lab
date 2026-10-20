#!/bin/bash
# SPLUNK-01 : application "eq13" (lecture JSON, 4 alertes temps reel -> webhook Shuffle), puis redemarrage.
set -e
# URL du webhook Shuffle (workflow cree par config/eq13_workflow.py, affichee a la fin de ce script)
HOOK="${1:-http://10.20.40.20:3001/api/v1/hooks/webhook_fffca616-f890-4a23-8d69-3b2b7bdaf5c9}"
APP=/opt/splunk/etc/apps/eq13
mkdir -p $APP/local $APP/default $APP/metadata
cat > $APP/default/app.conf <<'EOF'
[ui]
is_visible = true
label = EQ13 SOC
[launcher]
description = Detections du lab SOC EQ-13 (Kurger Bank)
version = 1.0
EOF
printf '[]\naccess = read : [ * ], write : [ admin ]\nexport = system\n' > $APP/metadata/local.meta

cat > $APP/local/props.conf <<'EOF'
[suricata:alert]
KV_MODE = json
SHOULD_LINEMERGE = false
TIME_PREFIX = "timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N%z
MAX_TIMESTAMP_LOOKAHEAD = 40

[eq13:fim]
KV_MODE = json
SHOULD_LINEMERGE = false
TIME_PREFIX = "time":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%SZ
TZ = UTC

[eq13:yara]
KV_MODE = json
SHOULD_LINEMERGE = false
TIME_PREFIX = "time":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%SZ
TZ = UTC
EOF


cat > $APP/local/savedsearches.conf <<EOF
[EQ13 P3 - Alerte reseau Suricata]
dispatch.earliest_time = rt-30s
dispatch.latest_time = rt
enableSched = 1
cron_schedule = * * * * *
alert.track = 1
action.webhook = 1
action.webhook.param.url = $HOOK
actions = webhook
search = index=eq13 sourcetype=suricata:alert event_type=alert alert.signature_id!=9000001 \
| eval eq13_priority="P3", eq13_iris_severity_id=1, eq13_title="Suricata : ".'alert.signature', eq13_detail='alert.category' \
| eval eq13_ip_attaquant=if(cidrmatch("10.20.21.0/27", src_ip) AND NOT cidrmatch("10.20.21.0/27", dest_ip), dest_ip, src_ip) \
| table _time host src_ip dest_ip eq13_ip_attaquant eq13_priority eq13_iris_severity_id eq13_title eq13_detail
alert_type = always
alert.digest_mode = 0
alert.suppress = 1
alert.suppress.fields = eq13_ip_attaquant,eq13_title
alert.suppress.period = 60s

[EQ13 P1 - Afflux HTTP anormal sur le service de paiement]
dispatch.earliest_time = rt-30s
dispatch.latest_time = rt
enableSched = 1
cron_schedule = * * * * *
alert.track = 1
action.webhook = 1
action.webhook.param.url = $HOOK
actions = webhook
search = index=eq13 sourcetype=suricata:alert event_type=alert alert.signature_id=9000001 \
| eval eq13_priority="P1", eq13_iris_severity_id=6, eq13_title="Afflux HTTP anormal sur le service de paiement", eq13_detail="Seuil : plus de 50 requetes en 10 s (MITRE T1498)" \
| eval eq13_ip_attaquant=if(cidrmatch("10.20.21.0/27", src_ip) AND NOT cidrmatch("10.20.21.0/27", dest_ip), dest_ip, src_ip) \
| table _time host src_ip dest_ip eq13_ip_attaquant eq13_priority eq13_iris_severity_id eq13_title eq13_detail
alert_type = always
alert.digest_mode = 0
alert.suppress = 1
alert.suppress.fields = eq13_ip_attaquant
alert.suppress.period = 60s
alert.severity = 6

[EQ13 P1 - YARA fichier malveillant]
dispatch.earliest_time = rt-30s
dispatch.latest_time = rt
enableSched = 1
cron_schedule = * * * * *
alert.track = 1
action.webhook = 1
action.webhook.param.url = $HOOK
actions = webhook
search = index=eq13 sourcetype=eq13:yara \
| eval eq13_priority="P1", eq13_iris_severity_id=6, eq13_title="YARA : fichier malveillant, regle ".yara_rule, eq13_detail=file." (sha256 ".sha256.")" \
| table _time host file sha256 yara_rule eq13_priority eq13_iris_severity_id eq13_title eq13_detail
alert_type = always
alert.digest_mode = 0
alert.suppress = 1
alert.suppress.fields = host,file,yara_rule
alert.suppress.period = 60s
alert.severity = 6

[EQ13 P1 - Chiffrement de masse par rancongiciel]
dispatch.latest_time = rt
enableSched = 1
cron_schedule = * * * * *
alert.track = 1
action.webhook = 1
action.webhook.param.url = $HOOK
actions = webhook
search = index=eq13 sourcetype=eq13:fim file="*.eq13locked" \
| stats dc(file) as fichiers, min(_time) as _time by host \
| where fichiers>=10 \
| eval eq13_priority="P1", eq13_iris_severity_id=6, eq13_title="Chiffrement de masse par rancongiciel", eq13_detail=fichiers." fichiers chiffres en moins de 60 s (MITRE T1486)" \
| table _time host fichiers eq13_priority eq13_iris_severity_id eq13_title eq13_detail
dispatch.earliest_time = rt-60s
alert_type = number of events
alert_comparator = greater than
alert_threshold = 0
alert.digest_mode = 0
alert.suppress = 1
alert.suppress.fields = host
alert.suppress.period = 120s
alert.severity = 6

[EQ13 P2 - Connexion privilegiee depuis une machine inhabituelle]
dispatch.earliest_time = rt-60s
dispatch.latest_time = rt
enableSched = 1
cron_schedule = * * * * *
alert.track = 1
action.webhook = 1
action.webhook.param.url = $HOOK
actions = webhook
search = index=eq13 sourcetype=linux_secure (Accepted) \
| rex "Accepted \w+ for (?<compte>\S+) from (?<src_ip>\d{1,3}(\.\d{1,3}){3})" \
| where isnotnull(src_ip) AND cidrmatch("10.20.50.0/28", src_ip) \
| eval eq13_ip_attaquant=src_ip, eq13_priority="P2", eq13_iris_severity_id=5, eq13_title="Connexion privilegiee depuis une machine inhabituelle", eq13_detail="Compte ".compte." connecte en SSH depuis ".src_ip." (segment d'attaque, MITRE T1078)" \
| table _time host compte src_ip eq13_ip_attaquant eq13_priority eq13_iris_severity_id eq13_title eq13_detail
alert_type = always
alert.digest_mode = 0
alert.suppress = 1
alert.suppress.fields = compte,src_ip
alert.suppress.period = 120s
alert.severity = 5
EOF
chown -R splunk:splunk $APP
/opt/splunk/bin/splunk btool savedsearches list --app=eq13 2>/dev/null | grep -c "^\[EQ13"
systemctl restart Splunkd
for i in $(seq 1 30); do sleep 5; curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8089/services/server/info | grep -q 401 && break; done
echo "Splunk redemarre"
