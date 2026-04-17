variable "hcloud_token" {
  description = "Hetzner Cloud API token. Leave null to use the HCLOUD_TOKEN environment variable."
  type        = string
  default     = null
  sensitive   = true
}

variable "instance_name" {
  description = "Hetzner Cloud server name"
  type        = string
  default     = "ctf-workstation"
}

variable "location" {
  description = "Hetzner Cloud location"
  type        = string
  default     = "nbg1"
}

variable "server_type" {
  description = "Hetzner Cloud server type"
  type        = string
  default     = "cx23"
}

variable "image" {
  description = "Hetzner Cloud image name"
  type        = string
  default     = "ubuntu-24.04"
}

variable "repo_path" {
  description = "Local path to the repository root copied to the VM"
  type        = string
  default     = "../.."
}

variable "ssh_public_key_path" {
  description = "Path to SSH public key file for root access"
  type        = string
  default     = "~/.ssh/id_rsa.pub"
}

variable "ssh_private_key_path" {
  description = "Path to the SSH private key matching ssh_public_key_path, used by the provisioner"
  type        = string
  default     = "~/.ssh/id_rsa"
}
