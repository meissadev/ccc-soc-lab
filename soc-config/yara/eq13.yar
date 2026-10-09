/*
  Regles YARA du labo SOC EQ-13 (CCC ANC 2026).
  Declenchees par Wazuh (FIM + reponse active) sur les dossiers surveilles.
*/

rule EQ13_Test_Marqueur
{
    meta:
        description = "Fichier de test EQ13 pour la demonstration YARA (inoffensif)"
        auteur = "EQ-13"
    strings:
        $m = "EQ13-YARA-TEST-MALWARE"
    condition:
        $m
}

rule EQ13_EICAR
{
    meta:
        description = "Fichier de test antivirus standard EICAR"
    strings:
        $e = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $e
}

rule EQ13_Webshell_PHP
{
    meta:
        description = "Webshell PHP : execution de commandes ou code obfusque"
        mitre = "T1505.003"
    strings:
        $obf = /eval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(/ nocase
        $cmd = /(system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        any of them
}

rule EQ13_Note_Rancon
{
    meta:
        description = "Note de rancon (scenario rancongiciel EQ13 et formulations courantes)"
        mitre = "T1486"
    strings:
        $n1 = "LISEZ-MOI-RANCON" nocase
        $n2 = "vos fichiers ont ete chiffres" nocase
        $n3 = "your files have been encrypted" nocase
        $n4 = "SIMULATION EQ13" nocase
    condition:
        any of them
}

rule EQ13_Outil_Vol_Identifiants
{
    meta:
        description = "Chaines caracteristiques de Mimikatz (vol d'identifiants)"
        mitre = "T1003.001"
    strings:
        $a = "sekurlsa::logonpasswords" nocase
        $b = "gentilkiwi" nocase
        $c = "lsadump::sam" nocase
    condition:
        any of them
}
