{ pkgs ? import ./nixpkgs.nix {} }:

with pkgs;

let
in
{
  py314 = stdenv.mkDerivation rec {
    name = "python314-with-poetry";

    buildInputs = [
      cacert
      git
      gnumake
      openssh
      python314
      python314Packages.pytest
      python314Packages.coincurve
      python314Packages.scikitlearn
      python314Packages.pycryptodome
      python314Packages.pynacl
    ];
  };

  py313 = stdenv.mkDerivation rec {
    name = "python313-with-poetry";

    buildInputs = [
      cacert
      git
      gnumake
      openssh
      python313
      python313Packages.pytest
      python313Packages.coincurve
      python313Packages.scikitlearn
      python313Packages.pycryptodome
      python313Packages.pynacl
    ];
  };

  py312 = stdenv.mkDerivation rec {
    name = "python312-with-poetry";

    buildInputs = [
      cacert
      git
      gnumake
      openssh
      python312
      python312Packages.pytest
      python312Packages.coincurve
      python312Packages.scikitlearn
      python312Packages.pycryptodome
      python312Packages.pynacl
    ];
  };
 
  py311 = stdenv.mkDerivation rec {
    name = "python311-with-poetry";

    buildInputs = [
      cacert
      git
      gnumake
      openssh
      python311
      python311Packages.pytest
      python311Packages.coincurve
      python311Packages.scikitlearn
      python311Packages.pycryptodome
      python311Packages.pynacl
    ];
  };

  py310 = stdenv.mkDerivation rec {
    name = "python310-with-poetry";

    buildInputs = [
      cacert
      git
      gnumake
      openssh
      python310
      python310Packages.pytest
      python310Packages.coincurve
      python310Packages.scikitlearn
      python310Packages.pycryptodome
      python310Packages.pynacl
    ];
  };
}
