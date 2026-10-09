# Configuration SOC appliquée à la main (hors Terraform)

Ces fichiers décrivent ce qui a été configuré sur les machines du labo après leur déploiement.
Ils servent de référence et permettent de refaire la configuration sur un labo recréé.
Aucun secret ici : la clé VirusTotal est saisie sur SOC-01 par `enable-virustotal.sh`.

## YARA (détection de fichiers malveillants)

Chaîne : fichier ajouté ou modifié dans un dossier surveillé → FIM Wazuh (règles 100200 à 100203)
→ réponse active YARA sur l'agent → résultat dans `active-responses.log` → règle 100221 (niveau 12, donc P1
vers Shuffle puis IRIS en *Critical*).

| Fichier | Emplacement sur la machine |
|---|---|
| `yara/eq13.yar` | SRV-WEB `/var/ossec/etc/yara/eq13.yar` · DC01 `C:\Program Files (x86)\ossec-agent\yara\eq13.yar` |
| `yara/yara.sh` | SRV-WEB `/var/ossec/active-response/bin/yara.sh` (root:wazuh, 750) |
| `yara/YaraAr.cs` | DC01, compilé en `active-response\bin\yara.exe` (l'agent Windows n'exécute que des `.exe`) |
| `wazuh/agent-srvweb-fim.xml` | Ajouté à `ossec.conf` de l'agent SRV-WEB |
| `wazuh/agent-dc01-fim.xml` | Ajouté à `ossec.conf` de l'agent DC01 |
| `wazuh/local_decoder-eq13.xml` | Manager : ajouté à `/var/ossec/etc/decoders/local_decoder.xml` |
| `wazuh/local_rules-eq13.xml` | Manager : ajouté à `/var/ossec/etc/rules/local_rules.xml` |
| `wazuh/ossec-manager-yara.xml` | Manager : ajouté à `/var/ossec/etc/ossec.conf` |

Binaires : YARA 4.1.3 (paquet Ubuntu) sur SRV-WEB, YARA 4.5.5 (release officielle win64) sur DC01.

Test (fichier inoffensif) :

- SRV-WEB : `echo 'EQ13-YARA-TEST-MALWARE' | sudo tee /opt/ccc/www/uploads/test.txt`
- DC01 : `Set-Content C:\Users\Public\Downloads\test.txt 'EQ13-YARA-TEST-MALWARE'`

Alerte attendue : « EQ13 YARA : fichier malveillant détecté, règle EQ13_Test_Marqueur » dans Wazuh, puis
« [EQ13] P1 - … » en *Critical* dans IRIS.

## VirusTotal

`wazuh/enable-virustotal.sh` est installé sur SOC-01 (`/opt/ccc/enable-virustotal.sh`). Il demande la clé API
sans l'afficher, ajoute l'intégration limitée aux règles 100200 à 100203 (quota gratuit : 4 requêtes/min,
500/jour), valide la configuration et redémarre le manager. Une détection donne la règle 87105 (niveau 12, P1).

```bash
sudo /opt/ccc/enable-virustotal.sh
```

Les empreintes (hash) des fichiers des dossiers surveillés sont envoyées au service VirusTotal.

## Point d'attention

Le workflow Shuffle insère `$exec.title` tel quel dans le JSON envoyé à IRIS : un titre d'alerte contenant
un chemin Windows (`c:\users\…`) rend ce JSON invalide (IRIS répond 400). Les règles EQ13 évitent donc les
chemins dans leurs descriptions ; le chemin reste dans le détail de l'alerte (`all_fields`).
