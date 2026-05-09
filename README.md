# whyblock

> **Why is my port blocked?** — Find out in one command.

`whyblock` is an open-source CLI tool that diagnoses AWS EC2 network connectivity issues instantly. Instead of manually checking Security Groups, NACLs, route tables, and Internet Gateways across multiple AWS console pages, you run one command and get a layer-by-layer verdict telling you exactly where traffic is being blocked — and how to fix it.

No SSH. No SSM. No instance access required.

---

## The Problem

When a port is unreachable on your EC2 instance, you have to check:

```
Security Group inbound rules     →  is the port allowed?
Security Group outbound rules    →  is return traffic allowed?
NACL inbound rules               →  is the subnet boundary open?
NACL outbound rules              →  stateless — must check both directions
Public IP                        →  does the instance have one?
Route table                      →  is there a default route to the IGW?
Internet Gateway                 →  is one attached to the VPC?
```

That is 7+ checks across 4–5 different AWS console pages. And rules interact — a Security Group might allow the port while a NACL silently drops it, and you would never connect those two facts just by looking at them separately.

**whyblock does all of this in one command, in under 5 seconds.**

---

## Demo

```
$ whyblock check --instance i-0abc123def456 --port 443

Checking i-0abc123def456 · port 443/tcp · from 0.0.0.0/0

LAYER               DETAIL                              VERDICT
──────────────────────────────────────────────────────────────────
Public IP           52.14.xxx.xxx                       ✓  assigned
Internet Gateway    igw-0abc123 attached to vpc-xxx     ✓  present
Route Table         0.0.0.0/0 → igw-0abc123             ✓  routed
NACL Inbound        Rule 100: ALLOW 0.0.0.0/0           ✓  allowed
Security Group      No rule for tcp:443                 ✗  BLOCKED
                    sg-001 allows: 22, 80 only

RESULT:  ✗  Blocked at Security Group (sg-001)
FIX:     Add inbound rule — TCP 443 from 0.0.0.0/0
LINK:    https://console.aws.amazon.com/ec2/v2/home#SecurityGroups:groupId=sg-001
```

```
$ whyblock check --instance i-0abc123def456 --port 443

LAYER               DETAIL                              VERDICT
──────────────────────────────────────────────────────────────────
Public IP           52.14.xxx.xxx                       ✓  assigned
Internet Gateway    igw-0abc123 attached to vpc-xxx     ✓  present
Route Table         0.0.0.0/0 → igw-0abc123             ✓  routed
NACL Inbound        Rule 100: ALLOW 0.0.0.0/0           ✓  allowed
Security Group      sg-001: ALLOW tcp:443               ✓  allowed
TCP Probe           SYN-ACK received (42ms)             ✓  open

RESULT:  ✓  Port 443 is reachable on i-0abc123def456
```

---

## How It Works

`whyblock` evaluates every network layer between the internet and your instance, top to bottom, stopping at the first block:

```
Internet
    │
    ▼
Layer 1 — Public IP          Does the instance have a public IP or Elastic IP?
    │
    ▼
Layer 2 — Internet Gateway   Is an IGW attached to the VPC?
    │
    ▼
Layer 3 — Route Table        Is there a 0.0.0.0/0 route pointing to the IGW?
    │
    ▼
Layer 4 — NACL               Do the subnet's Network ACL rules allow this traffic?
    │                        (stateless — evaluated in rule-number order)
    ▼
Layer 5 — Security Group     Do the instance's Security Group rules allow this port?
    │                        (stateful — all rules evaluated, no ordering)
    ▼
TCP Probe                    Real SYN handshake to confirm ground truth
    │
    ▼
Your Instance
```

After the AWS layer checks, `whyblock` performs a real TCP connection attempt and cross-references the result:

| AWS API says | TCP Probe says | Meaning |
|---|---|---|
| All layers ALLOW | Success | Fully open — port is reachable |
| All layers ALLOW | Timeout | OS-level firewall may be blocking (iptables/ufw) |
| All layers ALLOW | Refused | Port reached instance — app not listening or bound to 127.0.0.1 |
| Blocked at layer N | Timeout | Confirmed block at layer N |

---

## Installation

### Using Go

```bash
go install github.com/yourhandle/whyblock@latest
```

### Homebrew (macOS / Linux)

```bash
brew tap yourhandle/whyblock
brew install whyblock
```

### Download Binary

Download the latest binary for your platform from the [Releases](https://github.com/yourhandle/whyblock/releases) page.

```bash
# Linux (amd64)
curl -L https://github.com/yourhandle/whyblock/releases/latest/download/whyblock_linux_amd64.tar.gz | tar xz
sudo mv whyblock /usr/local/bin/

# macOS (Apple Silicon)
curl -L https://github.com/yourhandle/whyblock/releases/latest/download/whyblock_darwin_arm64.tar.gz | tar xz
sudo mv whyblock /usr/local/bin/
```

---

## AWS Credentials

`whyblock` uses your existing AWS credentials. It supports all standard AWS credential sources:

```bash
# Option 1 — AWS CLI profile (recommended)
whyblock check --instance i-0abc123 --port 443 --profile myprofile

# Option 2 — Environment variables
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
whyblock check --instance i-0abc123 --port 443

# Option 3 — IAM role (EC2 instance role or ECS task role)
# No configuration needed — credentials are picked up automatically
whyblock check --instance i-0abc123 --port 443
```

### Required IAM Permissions

`whyblock` is read-only. It only needs `Describe*` permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeRouteTables",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeAddresses"
      ],
      "Resource": "*"
    }
  ]
}
```

If any permission is missing, `whyblock` tells you exactly which ones are absent before running any checks.

---

## Commands

### `whyblock check` — Check if a port is reachable

```bash
whyblock check --instance <instance-id> --port <port> [flags]
```

| Flag | Description | Default |
|---|---|---|
| `--instance` | EC2 instance ID (required) | — |
| `--port` | Port number to check (required) | — |
| `--proto` | Protocol: `tcp` or `udp` | `tcp` |
| `--from` | Source IP, CIDR, or `internet` | `internet` (0.0.0.0/0) |
| `--timeout` | TCP probe timeout in seconds | `5` |
| `--output` | Output format: `table`, `json`, `yaml` | `table` |
| `--region` | AWS region | From AWS config |
| `--profile` | AWS profile name | From AWS config |

**Examples:**

```bash
# Check if port 443 is open from the internet
whyblock check --instance i-0abc123 --port 443

# Check if a specific IP can reach port 5432 (PostgreSQL)
whyblock check --instance i-0abc123 --port 5432 --from 10.0.1.45

# Check port 22 with JSON output (for scripting)
whyblock check --instance i-0abc123 --port 22 --output json

# Use a specific AWS profile and region
whyblock check --instance i-0abc123 --port 443 --profile prod --region ap-south-1
```

---

### `whyblock expose` — Show all ports reachable from the internet

```bash
whyblock expose --instance <instance-id> [flags]
```

Discovers every port on the instance that is effectively reachable from the internet (or a given source). Combines Security Group rules, NACL evaluation, and real TCP probes.

```bash
$ whyblock expose --instance i-0abc123

PORT      PROTO   SG RULE           NACL      TCP PROBE    WARNING
──────────────────────────────────────────────────────────────────────────
22        tcp     sg-001: ALLOW     ALLOW     ✓ open       ⚠ SSH exposed to 0.0.0.0/0
80        tcp     sg-001: ALLOW     ALLOW     ✓ open
443       tcp     sg-001: ALLOW     ALLOW     ✓ open
3306      tcp     sg-002: ALLOW     ALLOW     ✗ refused    ⚠ MySQL exposed to 0.0.0.0/0
8080      tcp     sg-001: ALLOW     DENY      ✗ timeout

SUMMARY
  3 ports fully reachable
  1 port open in SG but app not listening (3306)
  1 port open in SG but blocked by NACL (8080)
  2 sensitive ports exposed to 0.0.0.0/0  ← action recommended
```

**Flags:**

| Flag | Description | Default |
|---|---|---|
| `--from` | Source IP, CIDR, or `internet` | `internet` |
| `--output` | Output format: `table`, `json`, `yaml` | `table` |
| `--region` | AWS region | From AWS config |
| `--profile` | AWS profile name | From AWS config |

---

### `whyblock rules` — Dump all effective rules for an instance

```bash
whyblock rules --instance <instance-id> [flags]
```

Shows all attached Security Groups (inbound and outbound rules), NACL rules, route table, IGW status, and public IP — in one consolidated view.

```bash
$ whyblock rules --instance i-0abc123

Instance: i-0abc123  ·  52.14.xxx.xxx  ·  us-east-1a
VPC: vpc-0def456  ·  Subnet: subnet-0ghi789

SECURITY GROUPS
  sg-001 (web-server-sg)
    Inbound:   TCP  22    203.0.113.5/32   ALLOW
    Inbound:   TCP  80    0.0.0.0/0        ALLOW
    Outbound:  ALL  ALL   0.0.0.0/0        ALLOW

NETWORK ACL  (acl-0jkl012)
  Inbound:   Rule 100  TCP  0-65535  0.0.0.0/0   ALLOW
  Inbound:   Rule *    ALL  ALL      0.0.0.0/0   DENY
  Outbound:  Rule 100  ALL  ALL      0.0.0.0/0   ALLOW
  Outbound:  Rule *    ALL  ALL      0.0.0.0/0   DENY

ROUTE TABLE  (rtb-0mno345)
  10.0.0.0/16  →  local
  0.0.0.0/0    →  igw-0abc123

INTERNET GATEWAY  igw-0abc123  ·  attached  ✓
```

---

## Output Formats

All commands support `--output json` and `--output yaml` for scripting and CI/CD integration.

```bash
# JSON output
whyblock check --instance i-0abc123 --port 443 --output json
```

```json
{
  "instance": "i-0abc123",
  "port": 443,
  "proto": "tcp",
  "source": "0.0.0.0/0",
  "verdict": "BLOCKED",
  "blocked_at": "Security Group",
  "fix": "Add inbound rule — TCP 443 from 0.0.0.0/0",
  "console_url": "https://console.aws.amazon.com/ec2/v2/home#SecurityGroups:groupId=sg-001",
  "layers": [
    { "layer": "Public IP",         "detail": "52.14.xxx.xxx",              "status": "ALLOW" },
    { "layer": "Internet Gateway",  "detail": "igw-0abc123 attached",       "status": "ALLOW" },
    { "layer": "Route Table",       "detail": "0.0.0.0/0 → igw-0abc123",   "status": "ALLOW" },
    { "layer": "NACL Inbound",      "detail": "Rule 100: ALLOW 0.0.0.0/0", "status": "ALLOW" },
    { "layer": "Security Group",    "detail": "No rule for tcp:443",        "status": "BLOCK" }
  ],
  "probe": {
    "outcome": "TIMEOUT",
    "latency_ms": 5000
  }
}
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Port is reachable |
| `1` | Port is blocked |
| `2` | Error (invalid flags, AWS API failure, instance not found) |
| `3` | Completed with warnings (UDP probe skipped, instance stopped) |

Use exit codes in CI/CD pipelines:

```bash
whyblock check --instance i-0abc123 --port 443 --output json
if [ $? -eq 1 ]; then
  echo "Port blocked — failing deployment"
  exit 1
fi
```

---

## Why Not Use AWS Tools?

AWS provides two built-in tools for network analysis. Here is why `whyblock` is different:

| | VPC Reachability Analyzer | AWS Network Access Analyzer | whyblock |
|---|---|---|---|
| **Speed** | 2–3 minutes per check | Slow (compliance tool) | Under 5 seconds |
| **Cost** | $0.10 per analysis | Not free | Free (API calls only) |
| **Internet → Instance** | ✗ Not supported | ✗ Not supported | ✓ |
| **OS-level insight** | ✗ | ✗ | TCP probe (partial) |
| **Actionable fix + link** | ✗ | ✗ | ✓ |
| **CI/CD friendly** | ✗ | ✗ | ✓ JSON + exit codes |
| **Terminal native** | ✗ | ✗ | ✓ |

---

## Roadmap

- [x] AWS inbound connectivity check (`check` command)
- [x] Exposure report (`expose` command)
- [x] Rules dump (`rules` command)
- [ ] Outbound connectivity check (`whyblock check --to api.stripe.com`)
- [ ] Instance-to-instance check (`--from-instance` / `--to-instance`)
- [ ] Private instance support (via VPN / Direct Connect awareness)
- [ ] OS firewall check via SSM (optional, when SSM agent available)
- [ ] VPC Peering and Transit Gateway support
- [ ] Azure support
- [ ] GCP support

---

## Contributing

Contributions are welcome. Please open an issue before submitting a large PR so we can discuss the approach.
## Contributing

1. Fork the repository
2. Create a feature branch from `dev`
   git checkout -b feat/your-feature-name
3. Make your changes
4. Run make check before pushing
   make check
5. Push to your fork and open a PR targeting `dev`
6. Once reviewed and merged to dev, maintainer merges dev → main for releases

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgements

Built because every cloud engineer has wasted an afternoon on a port that was blocked by a NACL rule they forgot existed.