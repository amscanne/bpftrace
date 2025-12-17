# Buildkite Configuration Documentation

This repository uses Buildkite for CI/CD. The GitHub Actions workflows have been migrated to a modular Buildkite pipeline structure optimized for Nix.

## Pipeline Architecture

The pipeline is split into logical, reusable components:

### Main Orchestrator
- **`.buildkite/pipeline.yml`** - Main entry point that dynamically uploads sub-pipelines based on branch/event type

### Sub-Pipelines

1. **`.buildkite/pipeline.quality.yml`** - Code quality checks
   - clang-format
   - bpftrace-tidy
   - clang-tidy
   - stdlib documentation validation
   - Runs on: All branches and PRs

2. **`.buildkite/pipeline.ci.yml`** - Core build and test matrix
   - LLVM 17-21 builds (uses Buildkite matrix features)
   - Fuzzing tests
   - Latest kernel testing
   - AOT compilation tests
   - Runs on: master, release branches, and PRs

3. **`.buildkite/pipeline.distros.yml`** - Distribution builds
   - Alpine, Debian, Fedora, Ubuntu (uses matrix)
   - Runs on: master and release branches

4. **`.buildkite/pipeline.binary.yml`** - Binary artifacts
   - Static builds
   - AppImage for x86_64 and ARM64 (uses matrix)
   - Runs on: master and release branches

5. **`.buildkite/pipeline.codeql.yml`** - Security scanning
   - CodeQL analysis for C++ and Python
   - Runs on: master and release branches

6. **`.buildkite/pipeline.release.yml`** - Release builds
   - Build and upload release artifacts
   - Runs on: Git tags only

## Setup Instructions

### 1. Buildkite Organization Setup

1. Create a Buildkite account and organization
2. Create a new pipeline in Buildkite
3. Configure the pipeline to use this repository

### 2. Pipeline Configuration

In your Buildkite pipeline settings:

**Pipeline Settings > Steps**:
```yaml
steps:
  - command: buildkite-agent pipeline upload .buildkite/pipeline.yml
```

This uploads the main orchestrator which will dynamically load the appropriate sub-pipelines.

### 3. Agent Requirements

Your Buildkite agents need **Nix installed directly on the host** (not in Docker) to benefit from Nix caching.

#### Required on all agents:
- **Nix with flakes enabled** (`experimental-features = nix-command flakes` in nix.conf)
- **Git with submodule support**
- **Sudo access** for modprobe (kernel module loading)
- **Docker** (only for distro builds)

#### For BPF testing agents:
- **Kernel access**: `/dev` and `/sys/kernel/debug` must be accessible
- **KVM support** (for vmtest-based kernel testing)

#### Architecture-specific agents:
- Tag agents with `arch=x86_64` or `arch=arm64` for AppImage builds

### 4. Nix Cache Setup

To maximize build performance, set up a shared Nix cache:

#### Option A: Cachix (Recommended)

1. Sign up at https://cachix.org
2. Create a cache for your organization
3. Configure agents with Cachix:

```bash
# On each agent
cachix use <your-cache-name>

# For pushing to cache (requires auth token)
cachix authtoken <your-token>
```

4. Add to your agent's environment hooks (`~/.buildkite-agent/hooks/environment`):

```bash
#!/bin/bash
export CACHIX_SIGNING_KEY="<your-signing-key>"
```

5. Modify build commands to push to Cachix:

```bash
nix develop --command <build> | cachix push <your-cache-name>
```

#### Option B: Shared Nix Store (Local Network)

For agents on the same network:

1. Set up an NFS share or S3 bucket for the Nix store
2. Configure substituters in `/etc/nix/nix.conf`:

```conf
substituters = https://cache.nixos.org https://your-cache-url
trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY= your-cache-key
```

#### Option C: Binary Cache Server

Set up your own binary cache server:

```bash
# Using nix-serve
nix-shell -p nix-serve --run "nix-serve -p 5000"
```

Configure agents to use it via `/etc/nix/nix.conf` as in Option B.

#### Option D: Per-Agent Nix Store

If you can't share cache between agents, at least ensure:
- Nix store persists between builds on the same agent
- Use `keep-outputs = true` and `keep-derivations = true` in nix.conf

### 5. Environment Variables & Secrets

Configure in your Buildkite pipeline settings or agent environment:

- `GITHUB_TOKEN` - For release uploads (use Buildkite environment hooks)
- IRC notification credentials (if needed)

Example environment hook (`~/.buildkite-agent/hooks/environment`):

```bash
#!/bin/bash
set -euo pipefail

# Load secrets from your secrets manager
export GITHUB_TOKEN=$(aws secretsmanager get-secret-value --secret-id buildkite/github-token --query SecretString --output text)
```

### 6. Agent Configuration Example

Example `buildkite-agent.cfg`:

```toml
name="bpftrace-agent-%hostname-%spawn"
token="<your-agent-token>"
build-path="/var/lib/buildkite-agent/builds"
hooks-path="/var/lib/buildkite-agent/hooks"
plugins-path="/var/lib/buildkite-agent/plugins"

tags="queue=default,os=linux,arch=x86_64"
tags-from-host=true

# Allow more parallel jobs if you have the resources
spawn=3
```

### 7. Flake-specific Configuration

The GitHub Actions workflow used `DeterminateSystems/flakehub-cache-action`. For Buildkite:

1. **FlakeHub Cache** (if you have FlakeHub account):
   Add to your global git config on agents:
   ```bash
   git config --global url."https://flakehub.com/f".insteadOf "flakehub:"
   ```

2. **Determinate Systems Installer** (if you need it):
   You can install Nix using their installer on agents:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
   ```

### 8. Docker for Distro Builds

The distro builds still use Docker (since they test building on different OS environments):

- Ensure Docker daemon is running on agents
- Agent user must be in the `docker` group
- Consider Docker layer caching if available

## Branch/Event Filtering

The orchestrator automatically loads the right pipelines:

| Pipeline | master/release/* | PRs | Tags |
|----------|------------------|-----|------|
| quality  | ✓ | ✓ | ✓ |
| ci       | ✓ | ✓ | ✗ |
| distros  | ✓ | ✗ | ✗ |
| binary   | ✓ | ✗ | ✗ |
| codeql   | ✓ | ✗ | ✗ |
| release  | ✗ | ✗ | ✓ |

## Migration Notes

### Key Design Decisions

**Why no Docker plugin for Nix builds?**
- Docker containers don't persist the Nix store between builds
- Each container would rebuild everything from scratch
- Nix's caching works best with a persistent `/nix/store`
- Running Nix on the host agent is 10-100x faster with warm cache

**What about isolation?**
- Nix provides functional isolation through its store model
- Each build uses exact dependencies from flake.lock
- No dependency conflicts between builds
- Clean checkout per build provides additional isolation

### Differences from GitHub Actions

1. **Nix/Flakehub Cache**:
   - GitHub Actions: `DeterminateSystems/flakehub-cache-action`
   - Buildkite: Set up Cachix, binary cache, or shared Nix store (see above)

2. **Agent vs Container**:
   - GitHub Actions: Fresh Ubuntu container per job
   - Buildkite: Persistent agents with Nix installed
   - **Benefit**: Much faster builds with Nix cache

3. **KVM Configuration**:
   - GitHub Actions: `./.github/actions/configure_kvm`
   - Buildkite: Ensure agents have KVM enabled (`modprobe kvm`)

4. **IRC Notifications**:
   - Placeholder provided in CI pipeline
   - Implement using Buildkite notification plugins or custom script

5. **CodeQL**:
   - May require CodeQL CLI installation on agents
   - Or keep CodeQL on GitHub Actions (it's GitHub's tool anyway)

6. **Not Migrated**:
   - `issue-metrics.yml` - GitHub-specific, keep on GitHub Actions
   - `flakehub.yml` - Consider keeping on GitHub Actions

## Performance Expectations

With proper Nix caching:

| Build Type | Cold Cache | Warm Cache |
|------------|------------|------------|
| First LLVM build | 20-40 min | 2-5 min |
| Subsequent LLVM | 20-40 min | 30-60 sec |
| Quality checks | 5-10 min | 10-30 sec |
| AppImage | 15-30 min | 1-2 min |

Cold cache = first build ever or cache miss
Warm cache = Nix store has most dependencies

## Testing the Migration

1. Set up one test agent with Nix installed
2. Run individual pipelines manually:
   ```bash
   buildkite-agent pipeline upload .buildkite/pipeline.quality.yml
   ```
3. Verify Nix cache is working (second run should be much faster)
4. Compare results with GitHub Actions
5. Roll out to more agents

## Running Individual Pipelines

You can upload individual pipelines manually for testing:

```bash
buildkite-agent pipeline upload .buildkite/pipeline.quality.yml
buildkite-agent pipeline upload .buildkite/pipeline.ci.yml
# etc.
```

## Troubleshooting

### Slow builds despite caching

Check if Nix cache is working:
```bash
# On agent, check if cache is being used
nix build .#bpftrace-llvm21 --print-build-logs

# Should see "copying path ... from 'https://cache.nixos.org'" or your cache
# If you see "building ...", cache miss occurred
```

### Permission errors with /dev or /sys

Ensure agent user has necessary permissions:
```bash
# Add agent user to necessary groups
sudo usermod -aG kvm buildkite-agent
sudo usermod -aG docker buildkite-agent

# May need to configure udev rules for /sys/kernel/debug
```

### Nix flakes not enabled

Enable in `/etc/nix/nix.conf`:
```conf
experimental-features = nix-command flakes
```

Then restart Nix daemon:
```bash
sudo systemctl restart nix-daemon
```

## Best Practices

1. **Agent Maintenance**:
   - Periodically run `nix-collect-garbage` to free space
   - But keep recent builds: `nix-collect-garbage --delete-older-than 30d`

2. **Secrets Management**:
   - Use Buildkite environment hooks to inject secrets
   - Never commit secrets to pipeline files
   - Use a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.)

3. **Monitoring**:
   - Monitor agent disk usage (Nix store can grow large)
   - Set up alerts for failed builds
   - Track build times to detect cache issues

4. **Scaling**:
   - Start with 2-3 agents
   - Add more as needed for parallel matrix jobs
   - Consider autoscaling with AWS/GCP if using cloud agents

## Support

- Buildkite docs: https://buildkite.com/docs
- Buildkite matrix: https://buildkite.com/docs/pipelines/build-matrix
- Nix caching: https://nixos.org/manual/nix/stable/package-management/binary-cache-substituter.html
- Cachix: https://docs.cachix.org/
- Determinate Systems: https://determinate.systems/
