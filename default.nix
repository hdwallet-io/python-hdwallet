{ pkgs ? import ./nixpkgs.nix {} }:

with pkgs;

let
in
{
  py313 = stdenv.mkDerivation rec {
    name = "python313-with-pytest";

    buildInputs = [
      git
      openssh
      python313
      python313Packages.pytest
    ];
  };

  py312 = stdenv.mkDerivation rec {
    name = "python312-with-pytest";

    buildInputs = [
      git
      openssh
      python312
      python312Packages.pytest
    ];
  };
 
  py311 = stdenv.mkDerivation rec {
    name = "python311-with-pytest";

    buildInputs = [
      git
      openssh
      python311
      python311Packages.pytest
    ];
  };

  py310 = stdenv.mkDerivation rec {
    name = "python310-with-pytest";

    buildInputs = [
      git
      openssh
      python310
      python310Packages.pytest
    ];
  };

  py39 = stdenv.mkDerivation rec {
    name = "python39-with-pytest";

    buildInputs = [
      git
      openssh
      python39
      python39Packages.pytest
    ];
  };
}
