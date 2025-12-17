# Dynamic Buildkite Agent Provisioning Guide

This directory contains configurations for provisioning dynamic pools of Buildkite agents on NixOS.

## Overview

We provide several deployment options:

1. **AWS EC2 Autoscaling** (Terraform) - Recommended for production
2. **Manual NixOS Setup** - For existing infrastructure
3. **GCP/Azure** - Similar to AWS approach

## Quick Start - AWS with Terraform

### Prerequisites

- Terraform installed
- AWS credentials configured
- Buildkite agent token
- GitHub personal access token (for releases)

### Setup

1. **Create terraform.tfvars**:

```hcl
aws_region            = "us-west-2"
buildkite_agent_token = "your-buildkite-token"
github_token          = "your-github-token"
subnet_ids            = ["subnet-xxx", "subnet-yyy"]  # Your VPC subnets
min_agents            = 1
max_agents            = 10
instance_type         = "c6i.2xlarge"  # 8 vCPU, 16GB RAM
```

2. **Deploy**:

```bash
cd .buildkite/terraform
terraform init
terraform plan
terraform apply
```

3. **Verify**:

Check your Buildkite dashboard for connected agents.

## Architecture Details

### Instance Specifications

**Recommended: c6i.2xlarge**
- 8 vCPUs
- 16GB RAM
- Up to 10 Gbps network
- 3 concurrent build slots per instance
- ~$0.34/hour (adjust for region/spot pricing)

**For ARM64 builds: c6g.2xlarge**
- Graviton2 processors
- Same specs as c6i
- ~20% cost savings

### Storage

- **Root Volume**: 200GB gp3 SSD
  - Nix store needs significant space
  - Grows over time with builds
  - Automatic cleanup after 7 days

### Scaling Strategy

The Terraform configuration provides basic scaling policies. For production, consider:

#### Option A: Buildkite Elastic CI Stack

Use the official Buildkite stack (modified for NixOS):
- Scales based on queue depth
- More sophisticated than CloudWatch
- https://github.com/buildkite/elastic-ci-stack-for-aws

To adapt for NixOS:
1. Fork the stack
2. Replace the AMI with NixOS AMI
3. Modify user data to use our NixOS configuration

#### Option B: Custom Scaling

Add to `main.tf`:

```hcl
# Install Buildkite's scaling lambda
# This is more responsive than CloudWatch metrics
```

Or use the autoscaling script approach:
```bash
# Poll Buildkite API for queue depth
# Scale ASG based on demand
```

## NixOS AMI Options

### Official NixOS AMIs

AWS Marketplace AMIs (owner: 080433136561):
- NixOS 23.11 (recommended)
- NixOS unstable (latest packages)

Find latest:
```bash
aws ec2 describe-images \
  --owners 080433136561 \
  --filters "Name=name,Values=nixos-23.11-*-x86_64-linux" \
  --query 'Images | sort_by(@, &CreationDate) | [-1]'
```

### Custom AMI (Advanced)

Build your own with pre-cached Nix dependencies:

```bash
# Clone nixpkgs
git clone https://github.com/NixOS/nixpkgs

# Build custom AMI with bpftrace pre-cached
nix-build '<nixpkgs/nixos>' \
  -A config.system.build.amazonImage \
  -I nixos-config=./custom-ami.nix
```

Benefits:
- Faster startup (dependencies pre-cached)
- Consistent environment
- Can pre-load Nix store with common dependencies

## Nix Binary Cache Strategies

### Option 1: Cachix (Easiest)

```bash
# Create cache at cachix.org
cachix create bpftrace

# Add to NixOS config:
nix.settings.substituters = [ "https://bpftrace.cachix.org" ];
nix.settings.trusted-public-keys = [ "bpftrace.cachix.org-1:KEY" ];

# In agent hooks, push builds:
cachix watch-store bpftrace &
```

**Pros**: Managed, fast, reliable
**Cons**: Cost ($49+/mo), external dependency

### Option 2: S3 Binary Cache (Included in Terraform)

The Terraform config creates an S3 bucket for caching.

To configure signing (for writing):

```bash
# Generate signing key
nix-store --generate-binary-cache-key \
  bpftrace-cache-1 \
  /etc/nix/cache-priv-key.pem \
  /etc/nix/cache-pub-key.pem

# Add to agent environment:
export NIX_SECRET_KEY_FILE=/etc/nix/cache-priv-key.pem

# Push to cache:
nix copy --to 's3://bucket?region=us-west-2' /nix/store/path
```

**Pros**: Full control, no external service, low cost
**Cons**: More setup, need to manage keys

### Option 3: Shared EFS Nix Store

Mount a shared NFS/EFS volume for the Nix store:

```hcl
# In Terraform:
resource "aws_efs_file_system" "nix_store" {
  # ...
}

# Mount at /nix on all instances
```

**Pros**: True shared cache, fastest
**Cons**: More complex, potential lock contention, single point of failure

## Cost Optimization

### Use Spot Instances

Modify Terraform launch template:

```hcl
resource "aws_launch_template" "buildkite_agent" {
  # Add:
  instance_market_options {
    market_type = "spot"
    spot_options {
      max_price          = "0.15"  # ~50% discount
      spot_instance_type = "one-time"
    }
  }
}
```

**Pros**: 50-70% cost savings
**Cons**: Can be interrupted (but Buildkite handles this gracefully)

### Aggressive Scaling

Set `disconnect-after-job=true` so agents terminate when idle:
- Minimum agents: 0 (only run when needed)
- Scale up based on queue depth
- Save money during quiet periods

### Instance Scheduler

Use AWS Instance Scheduler to turn off agents at night/weekends:
```bash
# Only run agents during business hours
# Or only when PRs are likely to be created
```

## Monitoring

### CloudWatch Dashboards

Monitor:
- Agent count
- Build queue depth
- Nix store size
- Instance CPU/memory
- Network throughput
- Build success rate

### Buildkite Metrics

Use Buildkite's analytics to track:
- Build times (should be faster with Nix cache)
- Queue wait times
- Agent utilization

## Alternative: Using Existing Docker Images

If you want to use Docker instead of native NixOS, there are community options:

### nixos/nix Docker Image

```yaml
# In pipeline
plugins:
  - docker#v5.11.0:
      image: "nixos/nix:latest"
      volumes:
        - "/nix:/nix"  # Mount host Nix store
      environment:
        - "NIX_CONFIG=experimental-features = nix-command flakes"
```

**Issues**: Still need Nix store persistence, less efficient than native.

### Custom Docker Image with Buildkite Agent

```dockerfile
FROM nixos/nix:latest

# Install Buildkite agent
RUN nix-env -iA nixpkgs.buildkite-agent

# Configure
COPY buildkite-agent.cfg /etc/buildkite-agent/buildkite-agent.cfg
```

**Not recommended**: Adds complexity without benefits. Native NixOS is simpler.

## Troubleshooting

### Agents not connecting

Check:
```bash
# On instance:
sudo systemctl status buildkite-agent-*
sudo journalctl -u buildkite-agent-agent-1 -f
```

Verify token is correct:
```bash
cat /etc/buildkite-agent/token
```

### Slow builds despite caching

Check if cache is being used:
```bash
# On instance during build:
nix build .#bpftrace-llvm21 --print-build-logs

# Should see "copying path ... from ..." not "building ..."
```

Verify cache configuration:
```bash
nix show-config | grep substituters
```

### Running out of disk space

Increase root volume size in Terraform:
```hcl
volume_size = 300  # GB
```

Or run garbage collection more frequently:
```nix
nix.gc.options = "--delete-older-than 3d";
```

### Kernel module loading fails

Ensure KVM and permissions are correct:
```bash
ls -la /dev/kvm
# Should be accessible by buildkite-agent group

sudo modprobe kvm-intel  # or kvm-amd
```

## Next Steps

1. Deploy the Terraform stack to a test environment
2. Run a test build and verify caching works
3. Monitor costs and performance
4. Adjust instance types and scaling policies
5. Consider spot instances for production

## Support

- NixOS AMIs: https://github.com/NixOS/nixpkgs
- Buildkite AWS stack: https://github.com/buildkite/elastic-ci-stack-for-aws
- Cachix docs: https://docs.cachix.org
