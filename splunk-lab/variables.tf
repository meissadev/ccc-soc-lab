variable "region" {
  description = "Région AWS du laboratoire."
  type        = string
  default     = "eu-west-2"
}

variable "project" {
  description = "Valeur du tag 'projet' appliqué à toutes les ressources (identique au premier lab)."
  type        = string
  default     = "ccc-eq13"
}

variable "name_prefix" {
  description = "Préfixe des noms de ressources, distinct du premier lab (les rôles IAM ont des noms globaux)."
  type        = string
  default     = "ccc-eq13-splunk"
}

variable "availability_zone" {
  description = "AZ unique utilisée par les sous-réseaux."
  type        = string
  default     = "eu-west-2a"
}

# Types éligibles à l'offre gratuite en eu-west-2 uniquement.
variable "instance_types" {
  description = "Type d'instance par machine."
  type        = map(string)
  default = {
    splunk01 = "m7i-flex.large"
    soc02    = "m7i-flex.large"
    dc01     = "c7i-flex.large"
    srvweb   = "t3.small"
  }
}

variable "vlsm_enabled" {
  description = "Toujours vrai dans ce lab : le sous-réseau attaque existe (utilisé par network.tf)."
  type        = bool
  default     = true
}

# Le lab est désormais reconstruit à neuf par cloud-init (plus aucun clonage d'AMI).
variable "wazuh_version" {
  description = "Version de l'agent Wazuh installé sur DC01 et SRV-WEB (créé le dossier YARA, puis désactivé)."
  type        = string
  default     = "4.14.8"
}

variable "iris_version" {
  description = "Tag du dépôt dfir-iris/iris-web préparé sur SOC-02."
  type        = string
  default     = "v2.4.29"
}

variable "ad_domain" {
  description = "Nom DNS du domaine Active Directory de DC01."
  type        = string
  default     = "kurger.lab"
}
