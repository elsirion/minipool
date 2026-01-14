{
  description = "minipool - A Bitcoin mempool API service";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, crane, rust-overlay, advisory-db }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default;
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
        src = craneLib.cleanCargoSource ./.;

        # Build dependencies
        buildInputs = [];
        nativeBuildInputs = with pkgs; [ pkg-config ];

        # Common arguments that are used for both checking and building
        commonArgs = {
          src = craneLib.cleanCargoSource ./.;
          inherit buildInputs nativeBuildInputs;
        };

        # Build the crate
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;
        minipool = craneLib.buildPackage (
          commonArgs
          // {
            inherit cargoArtifacts;
          }
        );
        minipool-image = pkgs.dockerTools.buildLayeredImage {
          name = "minipool";
          contents = [
            minipool
            pkgs.bash
            pkgs.coreutils
            pkgs.curl
          ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.busybox ];

          config = {
            Cmd = [
              "${minipool}/bin/minipool"
            ];
          };
        };
      in
      {
        checks = {
          # Build the crates as part of `nix flake check` for convenience
          inherit minipool;

          # Run tests on the workspace source
          minipool-test = craneLib.cargoTest (commonArgs // {
            inherit cargoArtifacts;
          });

          # Run clippy (and deny all warnings) on the workspace source,
          # again, reusing the dependency artifacts from above.
          minipool-clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });

          minipool-doc = craneLib.cargoDoc (commonArgs // {
            inherit cargoArtifacts;
          });

          # Check formatting
          minipool-fmt = craneLib.cargoFmt {
            inherit src;
          };

          minipool-toml-fmt = craneLib.taploFmt {
            src = pkgs.lib.sources.sourceFilesBySuffices src [ ".toml" ];
          };

          # Audit dependencies
          minipool-audit-dependencies = craneLib.cargoAudit {
            inherit src advisory-db;
          };
        };

        packages = {
          inherit minipool minipool-image;
          default = minipool;
        };

        apps.default = flake-utils.lib.mkApp {
          drv = minipool;
        };

        devShells.default = craneLib.devShell {
          checks = self.checks.${system};
          
          packages = with pkgs; [
            # Rust toolchain
            rustToolchain
            rust-analyzer
            clippy
            rustfmt

            # Build dependencies
            pkg-config
            openssl

            # Development tools
            cargo-watch
            cargo-audit
            cargo-outdated
            cargo-edit
            just
          ];

          # Set up rust-analyzer for the project
          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
        };
      }) // {
        nixosModules.default = { config, lib, pkgs, ... }:
          with lib;
          let
            cfg = config.services.minipool;

          # Create wrapper script
          minipoolWrapper = pkgs.writeScriptBin "minipool-wrapper" ''
            #!${pkgs.bash}/bin/bash

            set -euo pipefail
            
            export BITCOIN_RPC_PASS="$(cat "$BITCOIN_RPC_PASS_FILE")"
            exec ${self.packages.${pkgs.system}.default}/bin/minipool "$@"
          '';
          in
          {
            options.services.minipool = {
              enable = mkEnableOption "minipool Bitcoin mempool API service";
              
              bindAddr = mkOption {
                type = types.str;
                default = "127.0.0.1:3000";
                description = "Address and port to bind the HTTP server to";
              };

              user = mkOption {
                type = types.str;
                default = "minipool";
                description = "User account under which minipool runs";
              };

              group = mkOption {
                type = types.str;
                default = "minipool";
                description = "Group account under which minipool runs";
              };

              bitcoinRpcUrl = mkOption {
                type = types.str;
                description = "Bitcoin RPC URL";
                example = "http://localhost:8332";
              };

              bitcoinRpcUser = mkOption {
                type = types.str;
                description = "Bitcoin RPC username";
              };

              bitcoinRpcPassFile = mkOption {
                type = types.path;
                description = "Path to file containing Bitcoin RPC password";
              };
            };

            config = mkIf cfg.enable {
              users.groups.${cfg.group} = {};
              users.users.${cfg.user} = {
                description = "minipool service user";
                group = cfg.group;
                isSystemUser = true;
              };

              systemd.services.minipool = {
                description = "minipool Bitcoin mempool API service";
                wantedBy = [ "multi-user.target" ];
                after = [ "network.target" ];

                serviceConfig = {
                  ExecStart = "${minipoolWrapper}/bin/minipool-wrapper";
                  User = cfg.user;
                  Group = cfg.group;
                  Restart = "always";
                  RestartSec = "10s";
                  
                  # Security hardening
                  CapabilityBoundingSet = "";
                  LockPersonality = true;
                  MemoryDenyWriteExecute = true;
                  NoNewPrivileges = true;
                  PrivateDevices = true;
                  PrivateTmp = true;
                  PrivateUsers = true;
                  ProtectClock = true;
                  ProtectControlGroups = true;
                  ProtectHome = true;
                  ProtectHostname = true;
                  ProtectKernelLogs = true;
                  ProtectKernelModules = true;
                  ProtectKernelTunables = true;
                  ProtectSystem = "strict";
                  RemoveIPC = true;
                  RestrictAddressFamilies = [ "AF_INET" "AF_INET6" ];
                  RestrictNamespaces = true;
                  RestrictRealtime = true;
                  RestrictSUIDSGID = true;
                  SystemCallArchitectures = "native";
                  SystemCallFilter = [ "@system-service" ];
                  UMask = "0077";

                  # Environment setup
                  Environment = [
                    "BIND_ADDR=${cfg.bindAddr}"
                    "BITCOIN_RPC_URL=${cfg.bitcoinRpcUrl}"
                    "BITCOIN_RPC_USER=${cfg.bitcoinRpcUser}"
                    "BITCOIN_RPC_PASS_FILE=${cfg.bitcoinRpcPassFile}"
                    "RUST_BACKTRACE=1"
                    "RUST_LOG=info"
                  ];
                };
              };
            };
          };
      };
}
