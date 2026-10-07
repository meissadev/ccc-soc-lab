# AMI publiques résolues via les paramètres SSM publiés par Canonical et AWS.

data "aws_ssm_parameter" "ubuntu_2204" {
  name = "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
}

data "aws_ssm_parameter" "windows_2022" {
  name = "/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base"
}

locals {
  ubuntu_ami  = data.aws_ssm_parameter.ubuntu_2204.insecure_value
  windows_ami = data.aws_ssm_parameter.windows_2022.insecure_value

  wazuh_manager_ip = local.ip.soc01

  instances = {
    soc01 = {
      name      = "SOC-01"
      ami       = local.ubuntu_ami
      subnet_id = aws_subnet.soc.id
      sg_id     = aws_security_group.soc.id
      disk_gb   = 30
      user_data = templatefile("${path.module}/cloud-init/soc-01.yaml", {
        wazuh_version = var.wazuh_version
      })
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
      user_data = templatefile("${path.module}/cloud-init/dc01.ps1", {
        domain           = var.ad_domain
        wazuh_version    = var.wazuh_version
        wazuh_manager_ip = local.wazuh_manager_ip
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
        wazuh_manager_ip = local.wazuh_manager_ip
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

  # Les instances *-flex et t3 en mode "standard" : pas de crédits CPU illimités
  # facturés en plus (t3 est "unlimited" par défaut).
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

    tags = merge(local.common_tags, { Name = "${each.value.name}-root" })
  }

  tags = { Name = each.value.name }

  lifecycle {
    # Évite de recréer les machines quand Canonical / AWS publient une nouvelle AMI
    # ou quand un script cloud-init est corrigé alors que le lab tourne.
    # Pour réinstaller une machine : terraform apply -replace='aws_instance.lab["soc02"]'
    ignore_changes = [ami, user_data]
  }

  depends_on = [
    aws_route_table_association.soc,
    aws_route_table_association.bank,
    aws_iam_role_policy_attachment.ssm_core,
  ]
}
