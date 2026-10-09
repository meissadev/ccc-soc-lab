locals {
  common_tags = {
    projet = var.project
  }

  vpc_cidr = "10.20.0.0/16"

  # Plan d'adressage. Sans VLSM : deux /24 identiques. Avec VLSM, chaque segment
  # reçoit le masque ajusté à son besoin (AWS réserve 5 adresses par sous-réseau) :
  #   soc     10.20.40.0/26  64 adresses (59 utilisables) : outils SOC + croissance
  #   bank    10.20.21.0/27  32 adresses (27 utilisables) : serveurs de la banque
  #   attaque 10.20.50.0/28  16 adresses (11 utilisables) : machines Red Team
  # Les IP fixes (.10, .11, .20, .30) restent valides dans les nouveaux masques.
  soc_cidr     = var.vlsm_enabled ? "10.20.40.0/26" : "10.20.40.0/24"
  bank_cidr    = var.vlsm_enabled ? "10.20.21.0/27" : "10.20.21.0/24"
  attaque_cidr = "10.20.50.0/28"

  # IP privées fixes (cidrhost = adresse n dans le sous-réseau).
  ip = {
    soc01  = cidrhost(local.soc_cidr, 11)  # 10.20.40.11
    soc02  = cidrhost(local.soc_cidr, 20)  # 10.20.40.20
    dc01   = cidrhost(local.bank_cidr, 10) # 10.20.21.10
    srvweb = cidrhost(local.bank_cidr, 30) # 10.20.21.30
  }
}
