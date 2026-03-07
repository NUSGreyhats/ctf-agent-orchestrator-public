variable "project_id" {
  description = "GCP project ID"
  type        = string
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

variable "boot_disk_size_gb" {
  description = "Boot disk size in GB"
  type        = number
  default     = 100
}

variable "all_things_ai_path" {
  description = "Local path to all-things-ai directory"
  type        = string
  default     = "~/all-things-ai"
}

variable "ssh_public_key_path" {
  description = "Path to SSH public key file for root access"
  type        = string
  default     = "~/.ssh/id_rsa.pub"
}
