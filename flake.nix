{
  description = "Persona directory-scoped identity guardrail";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

  outputs = { self, nixpkgs }:
    let
      # Native packages are validated on Apple Silicon macOS and both Linux architectures.
      systems = [ "aarch64-darwin" "aarch64-linux" "x86_64-linux" ];
      forEachSystem = nixpkgs.lib.genAttrs systems;

      runtimeTools = pkgs: [ pkgs.git pkgs.gnupg pkgs.openssh pkgs.gh ];
      testTools = pkgs: (runtimeTools pkgs) ++ [ pkgs.zsh pkgs.openssl pkgs.coreutils ];

      mkRustPackage = pkgs: extra:
        pkgs.rustPlatform.buildRustPackage ({
          pname = "persona";
          version = "0.1.0-rc.1";
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = testTools pkgs;
          doCheck = false;
        } // extra);
    in {
      packages = forEachSystem (system:
        let
          pkgs = import nixpkgs { inherit system; };
          persona = mkRustPackage pkgs {
            buildInputs = runtimeTools pkgs;
            nativeBuildInputs = (runtimeTools pkgs) ++ [ pkgs.makeWrapper ];
            postInstall = ''
              wrapProgram $out/bin/persona \
                --prefix PATH : ${pkgs.lib.makeBinPath (runtimeTools pkgs)} \
                --set PERSONA_INSTALL_EXECUTABLE $out/bin/persona
            '';
          };
        in {
          persona = persona;
          default = persona;
        });

      checks = forEachSystem (system:
        let
          pkgs = import nixpkgs { inherit system; };
          test = mkRustPackage pkgs {
            doCheck = true;
            PERSONA_TEST_GIT = "${pkgs.git}/bin/git";
            PERSONA_TEST_GPG = "${pkgs.gnupg}/bin/gpg";
            PERSONA_TEST_NATIVE_GH = "${pkgs.gh}/bin/gh";
            PERSONA_TEST_ZSH = "${pkgs.zsh}/bin/zsh";
            PERSONA_TEST_SSH = "${pkgs.openssh}/bin/ssh";
            PERSONA_TEST_SSH_KEYGEN = "${pkgs.openssh}/bin/ssh-keygen";
            PERSONA_TEST_SSH_AGENT = "${pkgs.openssh}/bin/ssh-agent";
            PERSONA_TEST_SSH_ADD = "${pkgs.openssh}/bin/ssh-add";
            PERSONA_TEST_SSHD = "${pkgs.openssh}/bin/sshd";
            PERSONA_TEST_OPENSSL = "${pkgs.openssl}/bin/openssl";
            PERSONA_TEST_CAT = "${pkgs.coreutils}/bin/cat";
            PERSONA_TEST_COREUTILS = "${pkgs.coreutils}/bin";
            PERSONA_TEST_SKIP_LOCAL_SSHD = "Nix sandbox cannot authenticate its builder user over loopback";
            PERSONA_TEST_SKIP_LOCAL_TLS = "Nix sandbox loopback TLS is not reliable for the local Git transport fixture";
            PERSONA_TEST_SKIP_LOCAL_HTTPS_PUSH = "Nix sandbox does not install the synthetic CA in system trust";
            checkPhase = ''
              cargo test --workspace --all-targets --locked -- --nocapture --test-threads=1
            '';
          };
          clippy = mkRustPackage pkgs {
            nativeBuildInputs = (testTools pkgs) ++ [ pkgs.clippy ];
            doCheck = true;
            checkPhase = ''
              cargo clippy --workspace --all-targets --locked -- -D warnings
            '';
          };
          fmt = pkgs.runCommand "persona-fmt" {
            nativeBuildInputs = [ pkgs.cargo pkgs.rustfmt pkgs.git ];
          } ''
            cp -R ${self} source
            chmod -R u+w source
            cd source
            cargo fmt --all -- --check
            touch $out
          '';
          installed-smoke = pkgs.runCommand "persona-installed-smoke" {
            nativeBuildInputs = [ pkgs.coreutils pkgs.gnugrep ];
          } ''
            export HOME="$TMPDIR/home"
            export XDG_CONFIG_HOME="$TMPDIR/config"
            export XDG_STATE_HOME="$TMPDIR/state"
            mkdir -m 700 -p "$HOME/bin" "$XDG_CONFIG_HOME" "$XDG_STATE_HOME"
            export PATH="$HOME/bin:${self.packages.${system}.persona}/bin:$PATH"
            install_output=$(${self.packages.${system}.persona}/bin/persona install apply --bin-dir "$HOME/bin")
            backup=$(printf '%s\n' "$install_output" | awk '/^Backup:/ { print $2 }')
            test -n "$backup"
            for shim in git gh ssh git-credential-persona; do
              test -L "$HOME/bin/$shim"
              test "$(readlink "$HOME/bin/$shim")" = "${self.packages.${system}.persona}/bin/persona"
            done
            set +e
            output=$("$HOME/bin/gh" repo view synthetic/repository 2>&1)
            status=$?
            set -e
            test "$status" -eq 126
            ! printf '%s' "$output" | grep -q 'absolute native GitHub CLI executable is required'
            printf '%s' "$output" | grep -q 'no Persona configuration'
            ${self.packages.${system}.persona}/bin/persona install refresh --apply
            remove_output=$(${self.packages.${system}.persona}/bin/persona install remove --apply)
            remove_backup=$(printf '%s\n' "$remove_output" | awk '/^Backup:/ { print $2 }')
            test -n "$remove_backup"
            for shim in git gh ssh git-credential-persona; do test ! -e "$HOME/bin/$shim"; done
            ${self.packages.${system}.persona}/bin/persona install rollback --backup "$remove_backup" --apply
            for shim in git gh ssh git-credential-persona; do test -L "$HOME/bin/$shim"; done
            ${self.packages.${system}.persona}/bin/persona install remove --apply
            for shim in git gh ssh git-credential-persona; do test ! -e "$HOME/bin/$shim"; done
            touch "$out"
          '';
        in {
          build = self.packages.${system}.persona;
          inherit test clippy fmt installed-smoke;
        });
    };
}
