#!/usr/bin/env bash
# Cloud-init user data script for setting up Buildkite agents on NixOS
# This can be used with AWS EC2, GCP, Azure, or other cloud providers

set -euo pipefail

# This script assumes you're using a NixOS AMI
# For AWS: https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/virtualisation/amazon-image.nix
# For GCP: https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/virtualisation/google-compute-image.nix

# Create Buildkite agent token file
mkdir -p /etc/buildkite-agent
echo "$BUILDKITE_AGENT_TOKEN" > /etc/buildkite-agent/token
chmod 600 /etc/buildkite-agent/token

# Create hooks directory
mkdir -p /etc/buildkite-agent/hooks

# Environment hook for secrets
cat > /etc/buildkite-agent/hooks/environment <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# Load secrets from your cloud provider's secrets manager
# AWS example:
# export GITHUB_TOKEN=$(aws secretsmanager get-secret-value \
#   --secret-id buildkite/github-token \
#   --query SecretString --output text)

# GCP example:
# export GITHUB_TOKEN=$(gcloud secrets versions access latest \
#   --secret="buildkite-github-token")

# Cachix configuration (if using)
# export CACHIX_SIGNING_KEY=$(aws secretsmanager get-secret-value \
#   --secret-id buildkite/cachix-signing-key \
#   --query SecretString --output text)

# Git configuration
git config --global user.email "buildkite@bpftrace.io"
git config --global user.name "Buildkite Agent"
EOF

chmod +x /etc/buildkite-agent/hooks/environment

# Pre-checkout hook for submodules
cat > /etc/buildkite-agent/hooks/pre-checkout <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# Enable git submodules
git config --global submodule.recurse true
EOF

chmod +x /etc/buildkite-agent/hooks/pre-checkout

# Post-checkout hook for Cachix (if using)
cat > /etc/buildkite-agent/hooks/post-checkout <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# Initialize Cachix watch-store for automatic uploads
if command -v cachix &> /dev/null; then
  cachix use bpftrace || true

  # If we have a signing key, watch the store
  if [ -n "${CACHIX_SIGNING_KEY:-}" ]; then
    cachix watch-store bpftrace &
  fi
fi
EOF

chmod +x /etc/buildkite-agent/hooks/post-checkout

# Create NixOS configuration
cat > /etc/nixos/buildkite-agent.nix <<'EOF'
{ config, pkgs, lib, ... }:

{
  imports = [
    # Include the base configuration
  ];

  # Enable Nix with flakes
  nix = {
    package = pkgs.nixFlakes;
    extraOptions = ''
      experimental-features = nix-command flakes
      keep-outputs = true
      keep-derivations = true
      max-jobs = auto
      cores = 0
    '';

    settings = {
      substituters = [
        "https://cache.nixos.org"
      ];
      trusted-public-keys = [
        "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
      ];
      trusted-users = [ "root" "buildkite-agent" ];
    };

    gc = {
      automatic = true;
      dates = "weekly";
      options = "--delete-older-than 30d";
    };
  };

  services.buildkite-agents.agents.agent-1 = {
    enable = true;
    tokenPath = "/etc/buildkite-agent/token";
    name = "bpftrace-%hostname-%n";
    tags = {
      queue = "default";
      os = "linux";
    };
    hooksPath = "/etc/buildkite-agent/hooks";
    runtimePackages = with pkgs; [
      bash git nix cachix docker gh python3
    ];
    extraConfig = ''
      spawn=3
      disconnect-after-job=true
    '';
  };

  virtualisation.docker.enable = true;
  boot.kernelModules = [ "kvm-intel" "kvm-amd" ];

  users.users.buildkite-agent.extraGroups = [ "docker" "kvm" ];

  security.sudo.extraRules = [{
    users = [ "buildkite-agent" ];
    commands = [{
      command = "${pkgs.kmod}/bin/modprobe";
      options = [ "NOPASSWD" ];
    }];
  }];

  environment.systemPackages = with pkgs; [
    git cachix docker gh python3
  ];
}
EOF

# Include in main configuration
if ! grep -q "buildkite-agent.nix" /etc/nixos/configuration.nix; then
  sed -i '/imports = \[/a \    ./buildkite-agent.nix' /etc/nixos/configuration.nix
fi

# Rebuild NixOS
nixos-rebuild switch

# Start the agent
systemctl enable buildkite-agent-agent-1
systemctl start buildkite-agent-agent-1

echo "Buildkite agent setup complete!"
