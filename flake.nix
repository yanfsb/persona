{
  description = "Persona directory-scoped identity auditor";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

  outputs = { self, nixpkgs }:
    let
      systems = [ "aarch64-darwin" ];
      forEachSystem = nixpkgs.lib.genAttrs systems;

      mkRustPackage = pkgs: extra:
        pkgs.rustPlatform.buildRustPackage ({
          pname = "persona";
          version = "0.1.0";
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = [ pkgs.git pkgs.gnupg ];
          doCheck = false;
        } // extra);
    in {
      packages = forEachSystem (system:
        let
          pkgs = import nixpkgs { inherit system; };
          persona = mkRustPackage pkgs {
            buildInputs = [ pkgs.git pkgs.gnupg ];
            nativeBuildInputs = [ pkgs.git pkgs.gnupg pkgs.makeWrapper ];
            postInstall = ''
              wrapProgram $out/bin/persona \
                --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.git pkgs.gnupg ]}
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
            checkPhase = ''
              cargo test --workspace --all-targets --locked
            '';
          };
          clippy = mkRustPackage pkgs {
            nativeBuildInputs = [ pkgs.git pkgs.gnupg pkgs.clippy ];
            doCheck = true;
            checkPhase = ''
              cargo clippy --workspace --all-targets --locked -- -D warnings
            '';
          };
          fmt = pkgs.runCommand "persona-fmt" {
            nativeBuildInputs = [ pkgs.cargo pkgs.rustfmt pkgs.git pkgs.gnupg ];
          } ''
            cp -R ${self} source
            chmod -R u+w source
            cd source
            cargo fmt --all -- --check
            touch $out
          '';
        in {
          build = self.packages.${system}.persona;
          inherit test clippy fmt;
        });
    };
}
