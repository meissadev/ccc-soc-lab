# SOC-02 (lab Splunk) : adapte le workflow EQ13 au format des alertes Splunk (sauvegarde : /root/wf-eq13.json).
# Usage : SH_U=... SH_P=... python3 shuffle_update.py /root/preparer_iris_splunk.py
import json, os, sys, urllib.request

BASE = "http://127.0.0.1:5001"
WF = "aca091bc-2f7f-4531-8660-1469ee51f716"


def req(method, path, body=None, headers=None):
    r = urllib.request.Request(BASE + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                               headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(r, timeout=30) as resp:
        return json.loads(resp.read().decode())


login = req("POST", "/api/v1/login", {"username": os.environ["SH_U"], "password": os.environ["SH_P"]})
tok = {c.get("key"): c.get("value") for c in login.get("cookies", []) if isinstance(c, dict)}.get("session_token", "")
api = req("GET", "/api/v1/me", headers={"Cookie": "session_token=" + tok}).get("apikey") or tok
h = {"Authorization": "Bearer " + api}

wf = req("GET", "/api/v1/workflows/" + WF, headers=h)
code = open(sys.argv[1], encoding="utf-8").read()
wf["name"] = "EQ13 - Triage alertes Splunk"
wf["description"] = "Alertes Splunk (webhook) -> IP -> MISP -> preparation -> DFIR-IRIS"
for t in wf.get("triggers", []):
    if t.get("trigger_type") == "WEBHOOK":
        t["label"] = "splunk-alerts"
for a in wf.get("actions", []):
    for p in a.get("parameters", []):
        if a.get("label") == "extraire_ip" and p.get("name") == "call":
            p["value"] = "$exec.result.src_ip"
        if a.get("label") == "preparer_iris" and p.get("name") == "code":
            p["value"] = code
res = req("PUT", "/api/v1/workflows/" + WF, wf, headers=h)
print("mise a jour :", res.get("success", res.get("name")))
chk = req("GET", "/api/v1/workflows/" + WF, headers=h)
print("nom :", chk.get("name"))
print("extraire_ip :", [p["value"] for a in chk["actions"] if a["label"] == "extraire_ip" for p in a["parameters"] if p["name"] == "call"])
print("code Splunk :", any("source:splunk" in (p.get("value") or "") for a in chk["actions"] for p in a["parameters"]))
