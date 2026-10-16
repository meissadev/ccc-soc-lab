# Noeud Shuffle "preparer_iris" (EQ13, lab Splunk) : construit le corps de l'alerte IRIS a partir
# d'une alerte Splunk (action webhook : {"result": {...}, "search_name", "sid", "results_link"}).
# - JSON toujours valide (json.dumps) ; resultat MISP repris ; IP de l'attaquant presume (calculee par Splunk) ajoutee comme IOC.
import json, re

def charge(texte, defaut):
    try:
        return json.loads(texte)
    except Exception:
        return defaut

alerte = charge(r'''$exec''', {})
resultat = alerte.get("result") or {}
ip = r'''$extraire_ip'''.strip()
if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
    ip = ""
misp = charge(r'''$recherche_misp''', {})

machine = resultat.get("host", "inconnue")
priorite = resultat.get("eq13_priority", "P?")
titre = resultat.get("eq13_title") or alerte.get("search_name", "Alerte Splunk")
detail = resultat.get("eq13_detail", "")

correspondances = []
if ip:
    corps = misp.get("body") if isinstance(misp, dict) else None
    attributs = ((corps or {}).get("response") or {}).get("Attribute") or [] if isinstance(corps, dict) else []
    for a in attributs:
        if a.get("value") == ip:
            correspondances.append("%s (evenement %s)" % ((a.get("Event") or {}).get("info", "?"), a.get("event_id", "?")))

if not ip:
    note_misp = "MISP : pas d'IP d'attaquant dans l'alerte, recherche non applicable"
elif correspondances:
    note_misp = "MISP : IP %s CONNUE - %s" % (ip, " ; ".join(correspondances))
else:
    note_misp = "MISP : IP %s inconnue" % ip

tags = ["source:splunk", "eq13:lab", priorite]
if correspondances:
    tags.append("misp:connu")

corps_iris = {
    "alert_title": "[EQ13] %s - %s" % (priorite, titre),
    "alert_description": "Machine : %s\nRecherche Splunk : %s\nDetail : %s\nIP de l'attaquant presume : %s (flux %s -> %s)\n%s" % (
        machine, alerte.get("search_name", "?"), detail or "-", ip or "-", resultat.get("src_ip", "-"), resultat.get("dest_ip", "-"), note_misp),
    "alert_source": "Splunk",
    "alert_source_ref": str(alerte.get("sid", "")),
    "alert_source_link": alerte.get("results_link", ""),
    "alert_severity_id": int(resultat.get("eq13_iris_severity_id", 1) or 1),
    "alert_status_id": 2,
    "alert_customer_id": 2,
    "alert_tags": ",".join(tags),
    "alert_note": note_misp,
    "alert_source_content": resultat,
    "alert_iocs": [],
}
if ip:
    corps_iris["alert_iocs"].append({
        "ioc_value": ip,
        "ioc_type_id": 79,
        "ioc_tlp_id": 2,
        "ioc_description": "IP de l'attaquant presume (alerte Splunk). " + note_misp,
        "ioc_tags": "source:splunk,eq13:lab",
    })

print(json.dumps(corps_iris))
