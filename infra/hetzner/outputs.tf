output "instance_name" {
  value = hcloud_server.ctf.name
}

output "external_ip" {
  value = hcloud_server.ctf.ipv4_address
}

output "webapp_url" {
  value = "https://${hcloud_server.ctf.ipv4_address}:8080"
}

output "webapp_password" {
  value     = data.local_file.webapp_password.content
  sensitive = true
}
