locals {
  common_tags = {
    projet = var.project
    lab    = "splunk"
  }

  # Même plan d'adressage VLSM que le premier lab, dans un VPC distinct et isolé (aucun peering) :
  # les machines clonées gardent leurs adresses et leur configuration.
  vpc_cidr     = "10.20.0.0/16"
  soc_cidr     = "10.20.40.0/26"
  bank_cidr    = "10.20.21.0/27"
  attaque_cidr = "10.20.50.0/28"

  ip = {
    splunk01 = cidrhost(local.soc_cidr, 11)  # 10.20.40.11 (remplace SOC-01 / Wazuh)
    soc02    = cidrhost(local.soc_cidr, 20)  # 10.20.40.20 (Shuffle, MISP, DFIR-IRIS)
    dc01     = cidrhost(local.bank_cidr, 10) # 10.20.21.10
    srvweb   = cidrhost(local.bank_cidr, 30) # 10.20.21.30
  }
}
