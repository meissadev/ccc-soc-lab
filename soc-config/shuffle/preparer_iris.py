# Noeud Shuffle "preparer_iris" (EQ13) : construit le corps de l'alerte IRIS.
# - JSON toujours valide (json.dumps), meme si le titre contient un chemin Windows ;
# - reprend le resultat MISP, ignore quand l'alerte n'a pas d'IP source ;
# - ajoute l'IP source comme IOC de l'alerte IRIS.
import json, re

def charge(texte, defaut):
    try:
        return json.loads(texte)
    except Exception:
        return defaut

alerte = charge(r'''$exec''', {})
ip = r'''$extraire_ip'''.strip()
if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
    ip = ""
misp = charge(r'''$recherche_misp''', {})

champs = alerte.get("all_fields") or {}
machine = (champs.get("agent") or {}).get("name", "inconnue")
priorite = alerte.get("eq13_priority", "P?")

correspondances = []
if ip:
    corps = misp.get("body") if isinstance(misp, dict) else None
    attributs = ((corps or {}).get("response") or {}).get("Attribute") or [] if isinstance(corps, dict) else []
    for a in attributs:
        if a.get("value") == ip:
            correspondances.append("%s (evenement %s)" % ((a.get("Event") or {}).get("info", "?"), a.get("event_id", "?")))

if not ip:
    note_misp = "MISP : pas d'IP source dans l'alerte, recherche non applicable"
elif correspondances:
    note_misp = "MISP : IP %s CONNUE - %s" % (ip, " ; ".join(correspondances))
else:
    note_misp = "MISP : IP %s inconnue" % ip

tags = ["source:wazuh", "eq13:lab", priorite]
if correspondances:
    tags.append("misp:connu")

corps_iris = {
    "alert_title": "[EQ13] %s - %s" % (priorite, alerte.get("title", "Alerte Wazuh")),
    "alert_description": "Machine : %s\nRegle Wazuh : %s\nIP source : %s\n%s" % (machine, alerte.get("rule_id", "?"), ip or "-", note_misp),
    "alert_source": "Wazuh",
    "alert_source_ref": str(alerte.get("id", "")),
    "alert_source_event_time": alerte.get("timestamp"),
    "alert_severity_id": int(alerte.get("eq13_iris_severity_id", 1)),
    "alert_status_id": 2,
    "alert_customer_id": 2,
    "alert_tags": ",".join(tags),
    "alert_note": note_misp,
    "alert_source_content": champs,
    "alert_iocs": [],
}
if ip:
    corps_iris["alert_iocs"].append({
        "ioc_value": ip,
        "ioc_type_id": 79,
        "ioc_tlp_id": 2,
        "ioc_description": "IP source de l'alerte Wazuh. " + note_misp,
        "ioc_tags": "source:wazuh,eq13:lab",
    })

print(json.dumps(corps_iris))
