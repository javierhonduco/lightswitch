{ pkgs }:
let

  kernel_5_15 = pkgs.stdenv.mkDerivation {
    name = "download-kernel-5.15";
    src = pkgs.fetchurl {
      url = "https://github.com/danobi/vmtest/releases/download/test_assets/bzImage-v5.15-fedora38";
      hash = "sha256-nq8W72vuNKCgO1OS6aJtAfg7AjHavRZ7WAkP7X6V610=";
    };
    dontUnpack = true;
    installPhase = ''
      mkdir -p $out
      cp -r $src $out/bzImage
    '';
  };

  kernel_6_0 = pkgs.stdenv.mkDerivation {
    name = "download-kernel-6.0";
    src = pkgs.fetchurl {
      url = "https://github.com/danobi/vmtest/releases/download/test_assets/bzImage-v6.0-fedora38";
      hash = "sha256-ZBBQ0yVUn+Isd2b+a32oMEbNo8T1v46P3rEtZ+1j9Ic=";
    };
    dontUnpack = true;
    installPhase = ''
      mkdir -p $out
      cp -r $src $out/bzImage
    '';
  };

  kernel_6_2 = pkgs.stdenv.mkDerivation {
    name = "download-kernel-6.2";
    src = pkgs.fetchurl {
      url = "https://github.com/danobi/vmtest/releases/download/test_assets/bzImage-v6.2-fedora38";
      hash = "sha256-YO2HEIWTuEEJts9JrW3V7UVR7t4J3+8On+tjdELa2m8=";
    };
    dontUnpack = true;
    installPhase = ''
      mkdir -p $out
      cp -r $src $out/bzImage
    '';
  };

  kernel_6_6 = pkgs.stdenv.mkDerivation {
    name = "download-kernel-6.6";
    src = pkgs.fetchurl {
      url = "https://github.com/danobi/vmtest/releases/download/test_assets/bzImage-v6.6-fedora38";
      hash = "sha256-6Fu16SPBITP0sI3lapkckZna6GKBn2hID038itt82jA=";
    };
    dontUnpack = true;
    installPhase = ''
      mkdir -p $out
      cp -r $src $out/bzImage
    '';
  };

  kernel_6_8_7 = pkgs.stdenv.mkDerivation {
    name = "download-kernel-6.8.7";
    src = pkgs.fetchurl {
      url = "https://github.com/javierhonduco/lightswitch-kernels/raw/c0af7a3/bzImage_v6.8.7";
      hash = "sha256-fZwGajRi9+otzokRxoss99aH9PLRuyl2UfJ5Echehdo=";
    };
    dontUnpack = true;
    installPhase = ''
      mkdir -p $out
      cp -r $src $out/bzImage
    '';
  };

  kernel_6_9_rc5 = pkgs.stdenv.mkDerivation {
    name = "download-kernel-6.9-rc5";
    src = pkgs.fetchurl {
      url = "https://github.com/javierhonduco/lightswitch-kernels/raw/c0af7a3/bzImage_v6.9-rc5";
      hash = "sha256-EA+nJ1M0/6QFPVA+fYkvXDhBcsmTnALpGr+tCJZsVyw=";
    };
    dontUnpack = true;
    installPhase = ''
      mkdir -p $out
      cp -r $src $out/bzImage
    '';
  };

  vmtest-create-config = lightswitch: pkgs.stdenv.mkDerivation {
    name = "vmtest-dump-config";
    dontUnpack = true;

    src = pkgs.writeText "vmtest.toml" ''
      [[target]]
      name = "Fedora 5.15"
      kernel = "${kernel_5_15}/bzImage"
      command = "${lightswitch}/bin/lightswitch --duration 0 --profile-format=none"

      [[target]]
      name = "Fedora 6.0"
      kernel = "${kernel_6_0}/bzImage"
      command = "${lightswitch}/bin/lightswitch --duration 0 --profile-format=none"

      [[target]]
      name = "Fedora 6.2"
      kernel = "${kernel_6_2}/bzImage"
      command = "${lightswitch}/bin/lightswitch --duration 0 --profile-format=none"

      [[target]]
      name = "Fedora 6.6"
      kernel = "${kernel_6_6}/bzImage"
      command = "${lightswitch}/bin/lightswitch --duration 0 --profile-format=none"

      [[target]]
      name = "Upstream 6.8.7"
      kernel = "${kernel_6_8_7}/bzImage"
      command = "${lightswitch}/bin/lightswitch --duration 0 --profile-format=none"

      [[target]]
      name = "Upstream v6.9-rc5"
      kernel = "${kernel_6_9_rc5}/bzImage"
      command = "${lightswitch}/bin/lightswitch --duration 0 --profile-format=none"
    '';
    nativeBuildInputs = [ ];
    installPhase = ''
      mkdir -p $out
      cp -r $src $out/vmtest.toml
    '';
  };

  vmtest = pkgs.rustPlatform.buildRustPackage {
    name = "vmtest";
    src = pkgs.fetchFromGitHub {
      owner = "danobi";
      repo = "vmtest";
      rev = "51f11bf301fea054342996802a16ed21fb5054f4";
      sha256 = "sha256-qtTq0dnDHi1ITfQzKrXz+1dRMymAFBivWpjXntD09+A=";
    };
    cargoHash = "sha256-SHjjCWz4FVVk1cczkMltRVEB3GK8jz2tVABNSlSZiUc=";
    # nativeCheckInputs = [ pkgs.qemu ];

    # There are some errors trying to access `/build/source/tests/*`.
    doCheck = false;

    meta = with pkgs.lib; {
      description = "Helps run tests in virtual machines";
      homepage = "https://github.com/danobi/vmtest/";
      license = licenses.asl20;
      mainProgram = "";
      maintainers = with maintainers; [ ];
      platforms = platforms.linux;
    };
  };
in
{
  run-vmtest = lightswitch:
    pkgs.writeShellScriptBin "run-vmtests" ''
      ${vmtest}/bin/vmtest --config ${vmtest-create-config lightswitch}/vmtest.toml
    '';
}
