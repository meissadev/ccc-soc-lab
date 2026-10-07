output "instances" {
  description = "Nom, id, IP privée et commande Session Manager de chaque instance."
  value = {
    for k, i in aws_instance.lab : local.instances[k].name => {
      id          = i.id
      private_ip  = i.private_ip
      ssm_command = "aws ssm start-session --target ${i.id} --profile claude-code --region ${var.region}"
    }
  }
}

output "port_forwarding" {
  description = "Commandes de redirection de port Session Manager vers les interfaces web (puis ouvrir l'URL indiquée)."
  value = {
    wazuh_dashboard = {
      command = "aws ssm start-session --target ${aws_instance.lab["soc01"].id} --document-name AWS-StartPortForwardingSession --parameters portNumber=443,localPortNumber=8443 --profile claude-code --region ${var.region}"
      url     = "https://localhost:8443"
    }
    misp = {
      command = "aws ssm start-session --target ${aws_instance.lab["soc02"].id} --document-name AWS-StartPortForwardingSession --parameters portNumber=443,localPortNumber=9443 --profile claude-code --region ${var.region}"
      url     = "https://localhost:9443"
    }
    shuffle = {
      command = "aws ssm start-session --target ${aws_instance.lab["soc02"].id} --document-name AWS-StartPortForwardingSession --parameters portNumber=3443,localPortNumber=3443 --profile claude-code --region ${var.region}"
      url     = "https://localhost:3443"
    }
    dfir_iris = {
      command = "aws ssm start-session --target ${aws_instance.lab["soc02"].id} --document-name AWS-StartPortForwardingSession --parameters portNumber=8443,localPortNumber=8444 --profile claude-code --region ${var.region}"
      url     = "https://localhost:8444 (après 'sudo /opt/ccc/iris-start.sh' sur SOC-02)"
    }
    dc01_rdp = {
      command = "aws ssm start-session --target ${aws_instance.lab["dc01"].id} --document-name AWS-StartPortForwardingSession --parameters portNumber=3389,localPortNumber=13389 --profile claude-code --region ${var.region}"
      url     = "mstsc /v:localhost:13389"
    }
  }
}

output "vpc_id" {
  value = aws_vpc.lab.id
}
