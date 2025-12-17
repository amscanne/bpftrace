# NixOS Buildkite Agent Configuration
# This is a NixOS module for configuring Buildkite agents with all requirements

{ config, pkgs, lib, ... }:

{
  # Enable Nix with flakes
  nix = {
    package = pkgs.nixFlakes;
    extraOptions = ''
      experimental-features = nix-command flakes
      keep-outputs = true
      keep-derivations = true
    '';

    settings = {
      # Cache configuration
      substituters = [
        "https://cache.nixos.org"
        # Add your Cachix cache here:
        # "https://bpftrace.cachix.org"
      ];
      trusted-public-keys = [
        "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
        # Add your Cachix public key here:
        # "bpftrace.cachix.org-1:your-key-here"
      ];

      # Allow building on agent
      trusted-users = [ "root" "buildkite-agent" ];
    };

    # Automatic garbage collection
    gc = {
      automatic = true;
      dates = "weekly";
      options = "--delete-older-than 30d";
    };
  };

  # Enable Buildkite agent
  services.buildkite-agents = {
    agents = {
      # You can create multiple agent instances
      bpftrace-1 = {
        enable = true;
        tokenPath = "/etc/buildkite-agent/token";

        # Agent configuration
        name = "bpftrace-nix-%hostname-%n";
        tags = {
          queue = "default";
          os = "linux";
          arch = "x86_64";  # or "arm64"
          nix = "true";
        };

        # Hooks directory
        hooksPath = "/etc/buildkite-agent/hooks";

        # Enable git mirrors for faster clones
        gitMirrorsPath = "/var/lib/buildkite-agent/git-mirrors";

        # Allow parallel builds
        runtimePackages = with pkgs; [
          bash
          git
          nix
          gitAndTools.git-lfs
          cachix  # If using Cachix
          docker  # For distro builds
          gh      # GitHub CLI for releases
        ];

        extraConfig = ''
          # Build isolation
          build-path="/var/lib/buildkite-agent/builds"
          plugins-path="/var/lib/buildkite-agent/plugins"

          # Allow up to 3 concurrent jobs (adjust based on instance size)
          spawn=3

          # Timeouts
          disconnect-after-job=true
          disconnect-after-job-timeout=120
        '';
      };
    };
  };

  # Docker for distro builds
  virtualisation.docker = {
    enable = true;
    autoPrune = {
      enable = true;
      dates = "weekly";
    };
  };

  # KVM for BPF tests
  boot.kernelModules = [ "kvm-intel" "kvm-amd" ];  # Adjust based on CPU

  # Required kernel modules for bpftrace tests
  boot.kernel.sysctl = {
    # Enable unprivileged BPF (optional, depends on security requirements)
    # "kernel.unprivileged_bpf_disabled" = 0;
  };

  # Ensure buildkite-agent user has necessary permissions
  users.users.buildkite-agent = {
    isSystemUser = true;
    group = "buildkite-agent";
    extraGroups = [ "docker" "kvm" ];
  };

  users.groups.buildkite-agent = {};

  # Sudo permissions for modprobe
  security.sudo.extraRules = [
    {
      users = [ "buildkite-agent" ];
      commands = [
        {
          command = "${pkgs.kmod}/bin/modprobe";
          options = [ "NOPASSWD" ];
        }
      ];
    }
  ];

  # Ensure /sys/kernel/debug is accessible
  systemd.tmpfiles.rules = [
    "d /sys/kernel/debug 0755 root root -"
  ];

  # Essential packages
  environment.systemPackages = with pkgs; [
    git
    git-lfs
    cachix
    docker
    gh
    python3
  ];

  # Networking
  networking.firewall.enable = true;

  # SSH for management
  services.openssh = {
    enable = true;
    settings = {
      PermitRootLogin = "no";
      PasswordAuthentication = false;
    };
  };

  # Automatic updates (optional)
  system.autoUpgrade = {
    enable = true;
    allowReboot = false;
    dates = "daily";
  };
}
