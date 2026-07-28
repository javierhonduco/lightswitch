{
  pkgs,
  lightswitch,
  enableKasan ? false,
  enableExtraAssertions ? false,
  requireKvm ? true,
}:

let
  inherit (pkgs) lib;

  kasanConfig = lib.optionalAttrs enableKasan (with lib.kernel; {
    KASAN = yes;
    KASAN_GENERIC = yes;
    KASAN_INLINE = yes;
    KASAN_VMALLOC = yes;
  });

  extraAssertionConfig = lib.optionalAttrs enableExtraAssertions (with lib.kernel; {
    DEBUG_KERNEL = yes;
    DEBUG_LIST = yes;
    DEBUG_NOTIFIERS = yes;
    DEBUG_PLIST = yes;
    DEBUG_SG = yes;
    DEBUG_VM = yes;
    PROVE_LOCKING = yes;
    PROVE_RCU = yes;
  });

  kernel = pkgs.linux_latest.override {
    structuredExtraConfig = kasanConfig // extraAssertionConfig;
    ignoreConfigErrors = false;
  };

  kernelPackages =
    if enableKasan || enableExtraAssertions
    then pkgs.linuxPackagesFor kernel
    else pkgs.linuxPackages_latest;

  name =
    "lightswitch-nixos-vmtest"
    + lib.optionalString enableKasan "-kasan"
    + lib.optionalString enableExtraAssertions "-assertions"
    + lib.optionalString (!requireKvm) "-no-kvm";
in
{
  inherit kernel kernelPackages;

  test = pkgs.testers.runNixOSTest {
    inherit name;
    requiredFeatures.kvm = requireKvm;

    nodes.machine =
      { pkgs, ... }:
      {
        boot.kernelPackages = kernelPackages;
        boot.kernel.sysctl = {
          "kernel.kptr_restrict" = 0;
          "kernel.perf_event_paranoid" = -1;
          "kernel.unprivileged_bpf_disabled" = 0;
        };

        environment.systemPackages = [
          lightswitch
          pkgs.bpftools
          pkgs.gnugrep
          pkgs.util-linux
        ];

        security.sudo.enable = false;

        virtualisation.cores = 2;
        virtualisation.memorySize = if enableKasan then 4096 else 2048;
      };

    testScript = ''
      machine.wait_for_unit("multi-user.target")

      with subtest("lightswitch reports system information"):
          print(machine.succeed("lightswitch system-info"))

      with subtest("lightswitch loads"):
          print(machine.succeed("lightswitch --duration 0 --sender none"))
    '';
  };
}
