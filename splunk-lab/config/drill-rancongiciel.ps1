# Simulation rancongiciel EQ13 (cyber drill, acte 1) - AUCUN fichier reel chiffre.
# A lancer sur DC01 (l'annuaire). Cree 12 "releves clients" factices et les renomme en .eq13locked
# en moins de 60 s, plus une note de rancon : declenche les alertes P1 "Chiffrement de masse" et
# P1 "YARA note de rancon" dans Splunk puis DFIR-IRIS.
$d = "C:\EQ13-Simu"
New-Item -ItemType Directory -Force -Path $d | Out-Null
Get-ChildItem $d -File -ErrorAction SilentlyContinue | Remove-Item -Force
foreach ($i in 1..12) {
  Set-Content -LiteralPath (Join-Path $d ("Releve-client-{0}.docx" -f $i)) -Value "Document fictif EQ13 $i"
}
Start-Sleep -Seconds 2
Get-ChildItem -LiteralPath $d -Filter *.docx | ForEach-Object {
  Rename-Item -LiteralPath $_.FullName -NewName ($_.Name + ".eq13locked")
}
Set-Content -LiteralPath (Join-Path $d "LISEZ-MOI-RANCON.txt") -Value "SIMULATION EQ13 - exercice de crise, aucun fichier reel chiffre"
Write-Output ("[EQ13] Fichiers .eq13locked crees : " + (Get-ChildItem $d -Filter *.eq13locked).Count + " (attendu : 12)")
