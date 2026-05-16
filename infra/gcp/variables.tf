variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "instance_name" {
  description = "GCP compute instance name"
  type        = string
  default     = "ctf-workstation"
}

variable "zone" {
  description = "GCP zone"
  type        = string
  default     = "asia-southeast1-c"
}

variable "machine_type" {
  description = "GCP machine type"
  type        = string
  default     = "e2-standard-4"
}

variable "image" {
  description = "GCP boot image"
  type        = string
  default     = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
}

variable "boot_disk_size_gb" {
  description = "Boot disk size in GB"
  type        = number
  default     = 100
}

variable "boot_disk_type" {
  description = "GCP boot disk type"
  type        = string
  default     = "pd-ssd"
}

variable "network" {
  description = "GCP VPC network name"
  type        = string
  default     = "default"
}

variable "subnetwork" {
  description = "GCP VPC subnetwork name (required for custom subnet mode networks)"
  type        = string
  default     = "default"
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
