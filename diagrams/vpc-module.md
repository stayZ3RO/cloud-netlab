# `network` Module + Drift Check

The reusable `network` module (VPC, public/private subnets across AZs, IGW,
routing, baseline SG) and the Python drift-check CLI that verifies live
state matches the Terraform declaration.

```mermaid
flowchart TB
    subgraph VPC["VPC: 10.0.0.0/16 (var.vpc_cidr)"]
        IGW["Internet Gateway"]
        subgraph AZA["AZ-a"]
            PUBA["public subnet"]
            PRVA["private subnet"]
        end
        subgraph AZB["AZ-b"]
            PUBB["public subnet"]
            PRVB["private subnet"]
        end
        RTPUB["public route table<br/>0.0.0.0/0 → IGW"]
        RTPRV["private route table<br/>local only"]
        SG["baseline security group<br/>deny inbound · allow egress"]

        IGW --- RTPUB
        RTPUB -. assoc .- PUBA
        RTPUB -. assoc .- PUBB
        RTPRV -. assoc .- PRVA
        RTPRV -. assoc .- PRVB
    end

    DRIFT["drift-check CLI: Python<br/>reads live VPC state via boto3<br/>diffs vs Terraform-declared state<br/>exits non-zero on drift<br/>101 pytest cases · runs in CI"]
    DRIFT -. inspects .-> VPC

    classDef aws fill:#1f2937,stroke:#f59e0b,color:#fde68a
    classDef sub fill:#0c4a6e,stroke:#38bdf8,color:#e0f2fe
    classDef tool fill:#166534,stroke:#4ade80,color:#dcfce7
    class IGW,RTPUB,RTPRV,SG aws
    class PUBA,PUBB,PRVA,PRVB sub
    class DRIFT tool
```

**OpenTofu / Terraform · consumed by `environments/dev` · no cloud
resources applied.** Subnet count is driven by the `azs` /
`public_subnet_cidrs` / `private_subnet_cidrs` variables, two AZs shown
here is the `dev` default, not a module limit.
