Make sure you have Terraform and the DigitalOcean CLI (`doctl`) set up, then:

```bash
cd ~/all-things-ai/infra
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars with your DigitalOcean API token

terraform init                          # download providers
terraform plan                          # preview what will be created
terraform apply                         # create the droplet and provision it

# Once done, SSH in with:
ssh root@$(terraform output -raw external_ip)

# To tear it down later:
terraform destroy
```

Get a DigitalOcean API token at: https://cloud.digitalocean.com/account/api/tokens

To verify or change the droplet size slug:
```bash
doctl compute size list | grep amd
```
