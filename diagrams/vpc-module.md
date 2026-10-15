# `network` Module + Drift Check

The reusable `network` module defines a VPC, public/private subnets across
availability zones, an internet gateway, public routing, and a baseline
security group.

```mermaid
flowchart TB
    subgraph VPC["VPC module"]
        IGW["Internet Gateway"]
        subgraph AZA["AZ-a"]
            PUBA["public subnet"]
            PRVA["private subnet"]
        end
        subgraph AZB["AZ-b"]
            PUBB["public subnet"]
            PRVB["private subnet"]
        end
        RTPUB["public route table<br/>default route to IGW"]
        SG["baseline security group<br/>deny inbound / allow egress"]

        RTPUB --> IGW
        PUBA --- RTPUB
        PUBB --- RTPUB
    end

    classDef aws fill:#1f2937,stroke:#f59e0b,color:#fde68a
    classDef sub fill:#0c4a6e,stroke:#38bdf8,color:#e0f2fe
    class IGW,RTPUB,SG aws
    class PUBA,PUBB,PRVA,PRVB sub
```

The Python CLI compares two supplied YAML snapshots. Each describes
subnets and DNS records, with optional security-group rules. It compares
normalized values and emits a text or JSON drift report.

```mermaid
flowchart LR
    DESIRED["Supplied desired YAML"] --> CLI["net-drift-check<br/>validate and compare"]
    ACTUAL["Supplied actual YAML"] --> CLI
    CLI --> REPORT["Text or JSON report<br/>0: no drift<br/>1: drift<br/>2: input error"]
```

The CLI reads local YAML files; it does not query AWS or read Terraform
state. See the [CLI documentation](../tools/net-drift-check/README.md) for
the input schema, normalization rules, and examples.

**OpenTofu / Terraform · consumed by `environments/dev` · no cloud
resources applied.** Subnet count is driven by the `azs` /
`public_subnet_cidrs` / `private_subnet_cidrs` variables. The two AZs shown
here are the `dev` default, not a module limit.
