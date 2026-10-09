#!/bin/bash
# EQ13 : active l'integration VirusTotal de Wazuh (SOC-01).
# La cle est saisie sans affichage et n'est ecrite que dans la configuration du manager.
# Chaque fichier ajoute ou modifie dans un dossier surveille (regles 100200 a 100203)
# est verifie par son empreinte : une detection donne la regle 87105 (niveau 12 => P1).
set -e
M=single-node-wazuh.manager-1
E=/var/ossec/etc
H=/opt/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf
TS=$(date +%Y%m%d-%H%M%S)

[ "$(id -u)" -eq 0 ] || { echo "Lancer avec sudo : sudo $0"; exit 1; }
read -rsp "Cle API VirusTotal (64 caracteres) : " KEY; echo
[[ "$KEY" =~ ^[0-9a-f]{64}$ ]] || { echo "Cle invalide : 64 caracteres hexadecimaux attendus."; exit 1; }

docker exec $M cp -a $E/ossec.conf $E/ossec.conf.bak-$TS
if docker exec $M grep -q '<!-- eq13-virustotal -->' $E/ossec.conf; then
  docker exec $M sed -i "s#<api_key>[0-9a-f]*</api_key><!-- eq13-virustotal -->#<api_key>$KEY</api_key><!-- eq13-virustotal -->#" $E/ossec.conf
else
  docker exec -i $M sh -c "cat >> $E/ossec.conf" <<XML

<!-- EQ13 : VirusTotal, limite aux dossiers surveilles (quota gratuit : 4 requetes/min, 500/jour) -->
<ossec_config>
  <integration>
    <name>virustotal</name>
    <api_key>$KEY</api_key><!-- eq13-virustotal -->
    <rule_id>100200,100201,100202,100203</rule_id>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
XML
fi

if ! docker exec $M /var/ossec/bin/wazuh-analysisd -t >/dev/null 2>&1; then
  docker exec $M cp -a $E/ossec.conf.bak-$TS $E/ossec.conf
  echo "Configuration invalide : retour a l'etat precedent."; exit 1
fi
docker exec $M /var/ossec/bin/wazuh-control restart >/dev/null 2>&1
sleep 20
docker exec $M /var/ossec/bin/wazuh-control status | grep -E "analysisd|integratord"
# Copie durable sur l'hote, lisible par root uniquement (contient la cle)
docker exec $M cat $E/ossec.conf > $H
chmod 640 $H
echo "VirusTotal active. Test : sur SRV-WEB, deposer le fichier EICAR dans /opt/ccc/www/uploads/"
