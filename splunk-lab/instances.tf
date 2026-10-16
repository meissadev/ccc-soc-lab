# Lab Splunk reconstruit entièrement à neuf (les AMI clonées du premier lab ont été
# supprimées le 10 octobre 2026). Les 4 machines sont déployées par cloud-init, puis
# converties pour Splunk par Run Command (dossier config/).
#
#   SPLUNK-01 : socle Ubuntu ; Splunk Enterprise (essai) installé ensuite par Run Command.
#   SOC-02    : MISP + Shuffle (démarrés) + DFIR-IRIS (préparé, arrêté).
#   DC01      : AD DS + DNS (kurger.lab) + Sysmon ; l'agent Wazuh est installé puis
#               désactivé par config/dc01-setup.ps1, qui pose l'Universal Forwarder.
#   SRV-WEB   : nginx + Suricata ; converti en Universal Forwarder par config/srv-web-setup.sh.

data "aws_ssm_parameter" "ubuntu_2204" {
  name = "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
}

data "aws_ssm_parameter" "windows_2022" {
  name = "/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base"
}

locals {
  ubuntu_ami  = data.aws_ssm_parameter.ubuntu_2204.insecure_value
  windows_ami = data.aws_ssm_parameter.windows_2022.insecure_value

  instances = {
    splunk01 = {
      name      = "SPLUNK-01"
      ami       = local.ubuntu_ami
      subnet_id = aws_subnet.soc.id
      sg_id     = aws_security_group.soc.id
      disk_gb   = 60
      user_data = file("${path.module}/cloud-init/splunk-01.yaml")
    }

    soc02 = {
      name      = "SOC-02"
      ami       = local.ubuntu_ami
      subnet_id = aws_subnet.soc.id
      sg_id     = aws_security_group.soc.id
      disk_gb   = 30
      user_data = templatefile("${path.module}/cloud-init/soc-02.yaml", {
        iris_version = var.iris_version
      })
    }

    dc01 = {
      name      = "DC01"
      ami       = local.windows_ami
      subnet_id = aws_subnet.bank.id
      sg_id     = aws_security_group.bank.id
      disk_gb   = 40
      # L'agent Wazuh est installé par le cloud-init (il crée le dossier ossec-agent
      # où YARA sera déployé), puis désactivé au profit de l'UF par config/dc01-setup.ps1.
      # Aucun manager Wazuh dans ce lab : on pointe l'agent sur SPLUNK-01 (connexion sans effet).
      user_data = templatefile("${path.module}/cloud-init/dc01.ps1", {
        domain           = var.ad_domain
        wazuh_version    = var.wazuh_version
        wazuh_manager_ip = local.ip.splunk01
      })
    }

    srvweb = {
      name      = "SRV-WEB"
      ami       = local.ubuntu_ami
      subnet_id = aws_subnet.bank.id
      sg_id     = aws_security_group.bank.id
      disk_gb   = 20
      user_data = templatefile("${path.module}/cloud-init/srv-web.yaml", {
        wazuh_version    = var.wazuh_version
        wazuh_manager_ip = local.ip.splunk01
        home_net         = local.vpc_cidr
      })
    }
  }
}

resource "aws_instance" "lab" {
  for_each = local.instances

  ami                    = each.value.ami
  instance_type          = var.instance_types[each.key]
  subnet_id              = each.value.subnet_id
  private_ip             = local.ip[each.key]
  vpc_security_group_ids = [each.value.sg_id]
  iam_instance_profile   = aws_iam_instance_profile.ssm.name

  # Pas de key pair : accès exclusivement via Session Manager.
  associate_public_ip_address = true
  user_data                   = each.value.user_data
  user_data_replace_on_change = true

  dynamic "credit_specification" {
    for_each = startswith(var.instance_types[each.key], "t") ? [1] : []
    content {
      cpu_credits = "standard"
    }
  }

  metadata_options {
    http_tokens   = "required" # IMDSv2 uniquement
    http_endpoint = "enabled"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = each.value.disk_gb
    encrypted             = true
    delete_on_termination = true
    tags                  = merge(local.common_tags, { Name = "${each.value.name}-splunklab-root" })
  }

  tags = { Name = "${each.value.name} (lab Splunk)" }

  # user_data ignoré après création : la config Splunk se fait par Run Command,
  # on ne veut pas recréer la machine si le cloud-init change.
  lifecycle {
    ignore_changes = [ami, user_data]
  }

  depends_on = [
    aws_route_table_association.soc,
    aws_route_table_association.bank,
    aws_iam_role_policy_attachment.ssm_core,
  ]
}
