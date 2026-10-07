locals {
  common_tags = {
    projet = var.project
  }

  vpc_cidr  = "10.20.0.0/16"
  soc_cidr  = "10.20.40.0/24"
  bank_cidr = "10.20.21.0/24"

  # IP privées fixes (cidrhost = adresse n dans le sous-réseau).
  ip = {
    soc01  = cidrhost(local.soc_cidr, 11)  # 10.20.40.11
    soc02  = cidrhost(local.soc_cidr, 20)  # 10.20.40.20
    dc01   = cidrhost(local.bank_cidr, 10) # 10.20.21.10
    srvweb = cidrhost(local.bank_cidr, 30) # 10.20.21.30
  }
}
