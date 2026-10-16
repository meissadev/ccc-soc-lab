output "instance_ids" {
  description = "Identifiants des instances du lab Splunk."
  value       = { for k, v in aws_instance.lab : k => v.id }
}

output "private_ips" {
  description = "Adresses privées."
  value       = local.ip
}

output "vpc_id" {
  value = aws_vpc.lab.id
}
