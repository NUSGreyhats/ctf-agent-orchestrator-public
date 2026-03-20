output "instance_name" {
  value = digitalocean_droplet.ctf.name
}

output "external_ip" {
  value = digitalocean_droplet.ctf.ipv4_address
}

output "webapp_url" {
  value = "https://${digitalocean_droplet.ctf.ipv4_address}:8080"
}
