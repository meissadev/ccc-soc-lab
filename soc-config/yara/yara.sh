#!/bin/bash
# Reponse active Wazuh (EQ13) : analyse YARA du fichier signale par la FIM.
# Le message JSON de Wazuh arrive sur l'entree standard ; le resultat est ecrit
# dans active-responses.log, que l'agent renvoie au manager (decodeur "wazuh-yara").
LOG=/var/ossec/logs/active-responses.log
YARA=/usr/bin/yara
RULES=/var/ossec/etc/yara/eq13.yar

read -r INPUT_JSON
FILE=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.syscheck.path // empty')
[ -n "$FILE" ] && [ -f "$FILE" ] || exit 0

sleep 1   # laisser l'ecriture du fichier se terminer
"$YARA" -w "$RULES" "$FILE" 2>/dev/null | while read -r RULE SCANNED; do
  echo "wazuh-yara: INFO - Scan result: $RULE $SCANNED" >> "$LOG"
done
exit 0
