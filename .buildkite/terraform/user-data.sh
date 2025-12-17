#!/usr/bin/env bash
# User data script for EC2 instances
# This is a template - variables are substituted by Terraform

set -euo pipefail

# Create Buildkite agent token
mkdir -p /etc/buildkite-agent
echo "${buildkite_agent_token}" > /etc/buildkite-agent/token
chmod 600 /etc/buildkite-agent/token

# Create hooks directory
mkdir -p /etc/buildkite-agent/hooks

# Environment hook for loading secrets
cat > /etc/buildkite-agent/hooks/environment <<'ENVEOF'
#!/usr/bin/env bash
set -euo pipefail

# Get instance metadata
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)

# Load GitHub token from Secrets Manager
export GITHUB_TOKEN=$(aws secretsmanager get-secret-value \
  --secret-id ${github_token_secret} \
  --region ${aws_region} \
  --query SecretString --output text)

# Git configuration
git config --global user.email "buildkite@bpftrace.io"
git config --global user.name "Buildkite Agent"
git config --global submodule.recurse true

# Add instance ID to build metadata
export BUILDKITE_AGENT_META_DATA_INSTANCE_ID="$INSTANCE_ID"
ENVEOF

chmod +x /etc/buildkite-agent/hooks/environment

# Pre-checkout hook
cat > /etc/buildkite-agent/hooks/pre-checkout <<'PRECHECKOUT'
#!/usr/bin/env bash
set -euo pipefail

# Initialize submodules
git config --global submodule.recurse true
PRECHECKOUT

chmod +x /etc/buildkite-agent/hooks/pre-checkout

# Create NixOS configuration for Buildkite
cat > /etc/nixos/buildkite.nix <<'NIXEOF'
{ config, pkgs, lib, ... }:

{
  # Nix configuration
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
        # S3 binary cache
        "s3://${nix_cache_bucket}?region=${aws_region}"
      ];
      trusted-public-keys = [
        "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
      ];
      trusted-users = [ "root" "buildkite-agent" ];
    };

    gc = {
      automatic = true;
      dates = "daily";
      options = "--delete-older-than 7d";
    };
  };

  # Buildkite agent
  services.buildkite-agents.agents = {
    agent-1 = {
      enable = true;
      tokenPath = "/etc/buildkite-agent/token";
      name = "bpftrace-%hostname-1";
      tags = {
        queue = "default";
        os = "linux";
        arch = "x86_64";
        instance-type = "c6i.2xlarge";
      };
      hooksPath = "/etc/buildkite-agent/hooks";
      runtimePackages = with pkgs; [
        bash git nix docker gh python3 awscli2
      ];
      extraConfig = ''
        spawn=1
        disconnect-after-job=true
        disconnect-after-job-timeout=120
      '';
    };

    agent-2 = {
      enable = true;
      tokenPath = "/etc/buildkite-agent/token";
      name = "bpftrace-%hostname-2";
      tags = {
        queue = "default";
        os = "linux";
        arch = "x86_64";
        instance-type = "c6i.2xlarge";
      };
      hooksPath = "/etc/buildkite-agent/hooks";
      runtimePackages = with pkgs; [
        bash git nix docker gh python3 awscli2
      ];
      extraConfig = ''
        spawn=1
        disconnect-after-job=true
        disconnect-after-job-timeout=120
      '';
    };

    agent-3 = {
      enable = true;
      tokenPath = "/etc/buildkite-agent/token";
      name = "bpftrace-%hostname-3";
      tags = {
        queue = "default";
        os = "linux";
        arch = "x86_64";
        instance-type = "c6i.2xlarge";
      };
      hooksPath = "/etc/buildkite-agent/hooks";
      runtimePackages = with pkgs; [
        bash git nix docker gh python3 awscli2
      ];
      extraConfig = ''
        spawn=1
        disconnect-after-job=true
        disconnect-after-job-timeout=120
      '';
    };
  };

  # Docker for distro builds
  virtualisation.docker = {
    enable = true;
    autoPrune.enable = true;
  };

  # KVM support
  boot.kernelModules = [ "kvm-intel" ];

  # User configuration
  users.users.buildkite-agent.extraGroups = [ "docker" "kvm" ];

  # Sudo for modprobe
  security.sudo.extraRules = [{
    users = [ "buildkite-agent" ];
    commands = [{
      command = "$${pkgs.kmod}/bin/modprobe";
      options = [ "NOPASSWD" ];
    }];
  }];

  # Packages
  environment.systemPackages = with pkgs; [
    git docker gh python3 awscli2 htop
  ];

  # CloudWatch monitoring (optional)
  # services.amazon-cloudwatch-agent.enable = true;
}
NIXEOF

# Add to main configuration
if ! grep -q "buildkite.nix" /etc/nixos/configuration.nix; then
  sed -i '/imports = \[/a \    ./buildkite.nix' /etc/nixos/configuration.nix
fi

# Rebuild and switch
nixos-rebuild switch

echo "Buildkite agent setup complete!"
