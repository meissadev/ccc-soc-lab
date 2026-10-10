#!/usr/bin/env python3
# EQ13 : reponse active Wazuh (SRV-WEB) - bloque l'IP source d'une alerte Suricata (champ data.src_ip)
# avec iptables, puis la debloque a l'expiration du delai (protocole "stateful" de Wazuh).
# A installer dans /var/ossec/active-response/bin/eq13-block-ip.py (root:wazuh, 750).
import json, subprocess, sys, datetime

LOG = "/var/ossec/logs/active-responses.log"
NEVER = {"10.20.40.11"}  # ne jamais bloquer le gestionnaire Wazuh


def log(msg):
    with open(LOG, "a") as f:
        f.write("%s eq13-block-ip: %s\n" % (datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S"), msg))


def ipt(action, ip):
    # INPUT pour les services de l'hote, DOCKER-USER pour les conteneurs (nginx du service de paiement)
    for chain in ("DOCKER-USER", "INPUT"):
        if subprocess.run(["iptables", "-L", chain, "-n"], capture_output=True).returncode != 0:
            continue
        rule = [chain, "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "eq13-ar"]
        exists = subprocess.run(["iptables", "-C"] + rule, capture_output=True).returncode == 0
        if action == "add" and not exists:
            subprocess.run(["iptables", "-I"] + rule, check=True)
        elif action == "delete" and exists:
            subprocess.run(["iptables", "-D"] + rule, check=True)


msg = json.loads(sys.stdin.readline())
command = msg.get("command")
alert = msg.get("parameters", {}).get("alert", {})
ip = alert.get("data", {}).get("src_ip") or alert.get("data", {}).get("srcip")
if not ip or ip in NEVER:
    log("aucune IP exploitable (%s)" % ip)
    sys.exit(0)

if command == "add":
    # Demande a Wazuh si ce blocage est deja actif (cle = IP)
    print(json.dumps({"version": 1, "origin": {"name": "eq13-block-ip", "module": "active-response"},
                      "command": "check_keys", "parameters": {"keys": [ip]}}), flush=True)
    resp = json.loads(sys.stdin.readline())
    if resp.get("command") != "continue":
        log("blocage deja actif pour %s" % ip)
        sys.exit(0)
    ipt("add", ip)
    log("IP %s bloquee (regle %s)" % (ip, alert.get("rule", {}).get("id")))
elif command == "delete":
    ipt("delete", ip)
    log("IP %s debloquee" % ip)
