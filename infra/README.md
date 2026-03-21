# Infrastructure

Two cloud providers are supported. Pick one and `cd` into its directory.

## Hetzner (`infra/hetzner/`)

```bash
cd infra/hetzner
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars with your Hetzner settings

terraform init
terraform plan
terraform apply

# Once done, SSH in with:
ssh -i ~/.ssh/id_rsa root@$(terraform output -raw external_ip)

# Get the web UI password:
terraform output -raw webapp_password

# Re-run only the long environment bootstrap:
terraform apply -replace=null_resource.setup_environment

# Re-deploy only the web app / service:
terraform apply -replace=null_resource.deploy_webapp

# To tear it down later:
terraform destroy
```

You can also omit `hcloud_token` from `terraform.tfvars` and export `HCLOUD_TOKEN` instead. Set `ssh_public_key_path` and `ssh_private_key_path` to a matching keypair if you are not using `~/.ssh/id_rsa(.pub)`.
Set `all_things_ai_path` to the repository root that contains `environment/` and `webapp/`. In this repo, `../..` is the correct value from `infra/hetzner/`.

## DigitalOcean (`infra/digitalocean/`)

Get a DigitalOcean API token at: https://cloud.digitalocean.com/account/api/tokens

```bash
cd infra/digitalocean
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars with your DigitalOcean API token

terraform init
terraform plan
terraform apply

# Once done, SSH in with:
ssh root@$(terraform output -raw external_ip)

# To tear it down later:
terraform destroy
```

To verify or change the droplet size slug:
```bash
doctl compute size list | grep amd
```
