# Met a jour le workflow Shuffle "EQ13 - Triage alertes Wazuh" via l'API Shuffle (SOC-02).
# Insere le noeud Python "preparer_iris" entre recherche_misp et le noeud IRIS.
# Usage : python3 update_workflow.py <apikey> <code_preparer_iris.py> [--dry-run]
import json, sys, uuid, copy, urllib.request

API = "http://localhost:5001/api/v1"
WF_ID = "aca091bc-2f7f-4531-8660-1469ee51f716"
key, code_file = sys.argv[1], sys.argv[2]
dry = "--dry-run" in sys.argv

def call(method, path, data=None):
    req = urllib.request.Request(API + path, method=method,
                                 data=json.dumps(data).encode() if data is not None else None,
                                 headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode())

wf = call("GET", "/workflows/" + WF_ID)
json.dump(wf, open("/root/shuffle-workflow-eq13.backup.json", "w"))   # sauvegarde avant modification
actions = {a["label"]: a for a in wf["actions"]}
print("noeuds actuels :", list(actions))
iris = next(a for a in wf["actions"] if a.get("app_name", "").upper().startswith("IRIS"))
misp = actions["recherche_misp"]
tools = actions["extraire_ip"]
code = open(code_file, encoding="utf-8").read()

if "preparer_iris" in actions:
    prep = actions["preparer_iris"]
    print("preparer_iris existe deja : mise a jour du code")
else:
    prep = copy.deepcopy(tools)
    prep["id"] = str(uuid.uuid4())
    prep["label"] = "preparer_iris"
    prep["name"] = "execute_python"
    prep["position"] = {"x": (misp["position"]["x"] + iris["position"]["x"]) / 2 + 120,
                        "y": (misp["position"]["y"] + iris["position"]["y"]) / 2}
    p = copy.deepcopy(tools["parameters"][0])
    p["name"] = "code"
    p["multiline"] = True
    prep["parameters"] = [p]
    wf["actions"].append(prep)
prep["parameters"][0]["value"] = code

# Branches : recherche_misp -> preparer_iris -> IRIS
template = copy.deepcopy(wf["branches"][0])
wf["branches"] = [b for b in wf["branches"]
                  if not (b["source_id"] == misp["id"] and b["destination_id"] == iris["id"])
                  and b["destination_id"] != prep["id"] and b["source_id"] != prep["id"]]
for src, dst in ((misp, prep), (prep, iris)):
    b = copy.deepcopy(template)
    b.update({"id": str(uuid.uuid4()), "source_id": src["id"], "destination_id": dst["id"], "conditions": []})
    wf["branches"].append(b)

# Corps IRIS = sortie du noeud Python
for prm in iris["parameters"]:
    if prm["name"] == "body":
        prm["value"] = "$preparer_iris.message"   # Shuffle Tools renvoie {"success", "message"}

labels = {a["id"]: a["label"] for a in wf["actions"]}
labels.update({t["id"]: t["label"] for t in wf.get("triggers", [])})
print("branches :", [(labels.get(b["source_id"]), labels.get(b["destination_id"])) for b in wf["branches"]])
if dry:
    print("dry-run : rien n'est envoye"); sys.exit(0)
res = call("PUT", "/workflows/" + WF_ID, wf)
print("enregistrement :", res.get("success", res) if isinstance(res, dict) else res)
