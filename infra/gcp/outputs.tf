output "instance_name" {
  value = google_compute_instance.ctf.name
}

output "external_ip" {
  value = google_compute_instance.ctf.network_interface[0].access_config[0].nat_ip
}

output "webapp_url" {
  value = "https://${google_compute_instance.ctf.network_interface[0].access_config[0].nat_ip}:8080"
}
