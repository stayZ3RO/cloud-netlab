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

The AWS resources are defined in code and have not been applied. The home network uses a UniFi UDM Pro and USW-24-PoE with a flat LAN; VLAN segmentation and inter-VLAN firewall policy remain planned.

| AWS concept | Home-network counterpart | Home status |
| --- | --- | --- |
| VPC | Network behind the edge firewall | Current flat LAN |
| Internet gateway | WAN uplink through the UDM Pro | Current network baseline |
| Public subnet | DMZ VLAN | Planned segmentation |
| Private subnet | Internal VLANs | Planned segmentation |
| Public route table | Default route out the WAN | Current flat-network routing |
| Baseline security group | Segmented firewall policy | Planned policy work |
