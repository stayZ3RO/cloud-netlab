# network module

Reusable AWS VPC building block: VPC, public + private subnets across AZs, an internet gateway, a public route table, and a baseline (deny-inbound / allow-egress) security group.

Written as a module, not copy-pasted HCL, so `environments/dev` (and a future `environments/prod`) consume the same code with different inputs. That's the "reusable module design" the role asks for and the thing my Proxmox homelab IaC didn't yet demonstrate.

## Inputs

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | (none) | Name prefix for all resources |
| `vpc_cidr` | string | `10.30.0.0/16` | VPC CIDR |
| `azs` | list(string) | `["us-east-1a","us-east-1b"]` | AZs to spread across |
| `public_subnet_cidrs` | list(string) | two /24s | Public subnet CIDRs (one per AZ) |
| `private_subnet_cidrs` | list(string) | two /24s | Private subnet CIDRs (one per AZ) |
| `tags` | map(string) | `{}` | Tags applied to everything |

## Outputs

`vpc_id`, `vpc_cidr`, `public_subnet_ids`, `private_subnet_ids`, `baseline_security_group_id`.

## Homelab mapping

| AWS resource | On-prem equivalent I already run |
| --- | --- |
| VPC | the routed network behind the edge firewall |
| Internet gateway | the WAN uplink (ER605) |
| Public subnet | DMZ VLAN |
| Private subnet | internal VLANs |
| Public route table | static default route out the WAN |
| Baseline security group | default-deny firewall policy |
