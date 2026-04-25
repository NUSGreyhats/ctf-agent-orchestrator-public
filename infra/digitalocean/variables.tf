variable "do_token" {
  description = "DigitalOcean API token"
  type        = string
  sensitive   = true
}

variable "instance_name" {
  description = "DigitalOcean droplet name"
  type        = string
  default     = "ctf-workstation"
}

variable "region" {
  description = "DigitalOcean region"
  type        = string
  default     = "fra1"
}

variable "droplet_size" {
  description = "DigitalOcean droplet size slug (verify with: doctl compute size list)"
  type        = string
  # Basic Shared CPU Premium AMD: 8 vCPU, 32 GB RAM, 400 GB NVMe SSD, 10 TB transfer
  default = "s-8vcpu-32gb-amd"
}

variable "droplet_image" {
  description = "DigitalOcean base image slug"
  type        = string
  default     = "ubuntu-24-04-x64"
}

variable "repo_path" {
  description = "Local path to the repository root"
  type        = string
  default     = "../.."
}

variable "ssh_public_key_path" {
  description = "Path to SSH public key file for root access"
  type        = string
  default     = "~/.ssh/id_rsa.pub"
}

variable "ssh_private_key_path" {
  description = "Path to SSH private key file"
  type        = string
  default     = "~/.ssh/id_rsa"
}
