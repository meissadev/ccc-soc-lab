variable "region" {
  description = "Région AWS du laboratoire."
  type        = string
  default     = "eu-west-2"
}

variable "project" {
  description = "Valeur du tag 'projet' appliqué à toutes les ressources."
  type        = string
  default     = "ccc-eq13"
}

variable "availability_zone" {
  description = "AZ unique utilisée par les deux sous-réseaux (pas de trafic inter-AZ facturé)."
  type        = string
  default     = "eu-west-2a"
}

variable "budget_alert_email" {
  description = "Adresse e-mail qui recevra les alertes AWS Budgets."
  type        = string

  validation {
    condition     = can(regex("^[^@ ]+@[^@ ]+[.][^@ ]+$", var.budget_alert_email))
    error_message = "budget_alert_email doit être une adresse e-mail valide."
  }
}

variable "budget_limit_usd" {
  description = "Montant mensuel (USD) du budget d'alerte."
  type        = number
  default     = 20
}

# Types d'instances : uniquement des types éligibles au free tier en eu-west-2
# (vérifiés avec 'aws ec2 describe-instance-types --filters Name=free-tier-eligible,Values=true').
variable "instance_types" {
  description = "Type d'instance par machine."
  type        = map(string)
  default = {
    soc01  = "m7i-flex.large"
    soc02  = "m7i-flex.large"
    dc01   = "c7i-flex.large"
    srvweb = "t3.small"
  }
}

variable "wazuh_version" {
  description = "Version de Wazuh (tag wazuh-docker et paquets agents)."
  type        = string
  default     = "4.14.8"
}

variable "iris_version" {
  description = "Tag du dépôt dfir-iris/iris-web."
  type        = string
  default     = "v2.4.29"
}

variable "ad_domain" {
  description = "Nom DNS du domaine Active Directory."
  type        = string
  default     = "kurger.lab"
}

# --- VLSM (remarque du jury) ---------------------------------------------------
# Activé le 9 octobre 2026. Le passage au VLSM a recréé les 4 instances (un sous-réseau
# AWS ne se redimensionne pas) depuis leurs AMI de sauvegarde (instance_amis), en
# conservant les IP privées et toute la configuration SOC.
variable "vlsm_enabled" {
  description = "Plan d'adressage VLSM : soc /26, bank /27, attaque /28, et segmentation fine des groupes de sécurité."
  type        = bool
  default     = true
}

variable "instance_amis" {
  description = "AMI de sauvegarde à utiliser par machine (soc01, soc02, dc01, srvweb) lors d'une recréation."
  type        = map(string)
  default     = {}
}
