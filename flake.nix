{
  description = "Python HD Wallet development environment with multiple Python versions";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/25.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        
        # Create Python environments with required packages
        mkPythonEnv = pythonPkg: pythonPkg.withPackages (ps: with ps; [
          pytest
          coincurve
          scikit-learn
          pycryptodome
          pynacl
        ]);

        python310Env = mkPythonEnv pkgs.python310;
        python311Env = mkPythonEnv pkgs.python311;
        python312Env = mkPythonEnv pkgs.python312;
        python313Env = mkPythonEnv pkgs.python313;
        python314Env = mkPythonEnv pkgs.python314;

      in {
        # Single development shell with all Python versions
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Common tools
            cacert
            git
            gnumake
            openssh
            bash
            bash-completion

            # All Python versions with packages
            #python310Env
            python311Env
            python312Env
            python313Env
            #python314Env
          ];

          shellHook = ''
            echo "Welcome to the multi-Python development environment!"
            echo "Available Python interpreters:"
            echo "  python (default): $(python --version 2>&1 || echo 'not available')"
           #echo "  python3.10: $(python3.10 --version 2>&1 || echo 'not available')"
            echo "  python3.11: $(python3.11 --version 2>&1 || echo 'not available')"
            echo "  python3.12: $(python3.12 --version 2>&1 || echo 'not available')"
            echo "  python3.13: $(python3.13 --version 2>&1 || echo 'not available')"
           #echo "  python3.14: $(python3.14 --version 2>&1 || echo 'not available')"
            echo ""
            echo "All versions have pytest, coincurve, scikit-learn, pycryptodome, and pynacl installed."
          '';
        };
      });
}
