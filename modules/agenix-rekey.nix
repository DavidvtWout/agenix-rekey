nixpkgs:
{ lib, options, config, pkgs, ... }:
let
  inherit (lib)
    all concatMapStrings filter flatten flip hasAttr hasPrefix hasSuffix isPath
    isString literalExpression mapAttrs mapAttrs' mapAttrsToList mkIf mkOption
    mkRenamedOptionModule nameValuePair optional readFile showOptionWithDefLocs
    substring types;

  # This pubkey is just binary 0x01 in each byte, so you can be sure there is no known private key for this
  dummyPubkey =
    "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq";
  isAbsolutePath = x: substring 0 1 x == "/";
  rekeyHostPkgs = if config.age.rekey.forceRekeyOnSystem == null then
    pkgs
  else
    import nixpkgs { system = config.age.rekey.forceRekeyOnSystem; };
  rekeyedSecrets = import ../nix/output-derivation.nix {
    appHostPkgs = rekeyHostPkgs;
    hostConfig = config;
  };
in {
  config = {
    assertions = [
      {
        assertion = config.age.rekey.masterIdentities != [ ];
        message = "rekey.masterIdentities must be set.";
      }
      {
        assertion = all isAbsolutePath config.age.rekey.masterIdentities;
        message =
          "All masterIdentities must be referred to by an absolute path, but (${
            filter isAbsolutePath config.age.rekey.masterIdentities
          }) is not.";
      }
    ];

    warnings = let
      hasGoodSuffix = x:
        (hasPrefix builtins.storeDir x)
        -> (hasSuffix ".age" x || hasSuffix ".pub" x);
    in optional (!all hasGoodSuffix config.age.rekey.masterIdentities) ''
      At least one of your rekey.masterIdentities references an unencrypted age identity in your nix store!
      ${concatMapStrings (x: "  - ${x}\n")
      (filter hasGoodSuffix config.age.rekey.masterIdentities)}

      These files have already been copied to the nix store, and are now publicly readable!
      Please make sure they don't contain any secret information or delete them now.

      To silence this warning, you may:
        - Use a split-identity ending in `.pub`, where the private part is not contained (a yubikey identity)
        - Use an absolute path to your key outside of the nix store ("/home/myuser/age-master-key")
        - Or encrypt your age identity and use the extension `.age`. You can encrypt an age identity
          using `rage -p -o privkey.age privkey` which protects it in your store.
    '' ++ optional (config.age.rekey.hostPubkey == dummyPubkey) ''
      You have not yet specified rekey.hostPubkey for your host ${config.networking.hostName}.
      All secrets for this host will be rekeyed with a dummy key, resulting in an activation failure.

      This is intentional so you can initially deploy your system to read the actual pubkey.
      Once you have the pubkey, set rekey.hostPubkey to the content or a file containing the pubkey.
    '';
  };

  imports = [
    ({ config, options, ... }: {
      config = {
        age.secrets = mapAttrs (_: secret:
          mapAttrs' (n: nameValuePair (if n == "file" then "rekeyFile" else n))
          secret) config.rekey.secrets;
      };
    })
  ];

  options.age = {
    # Extend age.secrets with new options
    secrets = mkOption {
      type = types.attrsOf (types.submodule (submod: {
        options = {
          id = mkOption {
            type = types.str;
            default = submod.config._module.args.name;
            readOnly = true;
            description =
              "The true identifier of this secret as used in `age.secrets`.";
          };

          rekeyFile = mkOption {
            type = types.nullOr types.path;
            default = if config.age.rekey.generatedSecretsDir != null then
              config.age.rekey.generatedSecretsDir + "/${submod.config.id}.age"
            else
              null;
            example = literalExpression "./secrets/password.age";
            description = ''
              The path to the encrypted .age file for this secret. The file must
              be encrypted with one of the given `age.rekey.masterIdentities` and not with
              a host-specific key.

              This secret will automatically be rekeyed for hosts that use it, and the resulting
              host-specific .age file will be set as actual `file` attribute. So naturally this
              is mutually exclusive with specifying `file` directly.

              If you want to avoid having a `secrets.nix` file and only use rekeyed secrets,
              you should always use this option instead of `file`.
            '';
          };
        };
        config = {
          # Produce a rekeyed age secret
          file = mkIf (submod.config.rekeyFile != null)
            "${rekeyedSecrets}/${submod.config.name}.age";
        };
      }));
    };

    rekey = {
      derivation = mkOption {
        type = types.package;
        default = rekeyedSecrets;
        readOnly = true;
        description = ''
          The derivation that contains the rekeyed secrets.
          Cannot be built directly, use `agenix rekey` instead.
        '';
      };
      generatedSecretsDir = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = ''
          The path where all generated secrets should be stored by default.
          If set, this automatically sets `age.secrets.<name>.rekeyFile` to a default
          value in this directory, for any secret that defines a generator.
        '';
      };
      cacheDir = mkOption {
        type = types.str;
        default = ''/tmp/agenix-rekey."$UID"'';
        example = ''/var/tmp/agenix-rekey."$UID"'';
        description = ''
          This is the directory where we store the rekeyed secrets
          so that they can be found later by the derivation builder.

          Must be a bash expression that expands to the directory to use
          as a cache. By default the cache is kept in /tmp, but you can
          change it (see example) to persist the cache across reboots.
          The directory must be readable by the nix build users. Make
          sure to use corret quoting, this _must_ be a bash expression
          resulting in a single string.

          The actual secrets will be stored in the directory based on their input
          content hash (derived from host pubkey and file content hash), and stored
          as `''${cacheDir}/secrets/<ident-sha256>-<filename>`. This allows us to
          reuse already existing rekeyed secrets when rekeying again, while providing
          a deterministic path for each secret.
        '';
      };
      forceRekeyOnSystem = mkOption {
        type = types.nullOr types.str;
        description = ''
          If set, this will force that all secrets are rekeyed on a system of the given architecture.
          This is important if you have several hosts with different architectures, since you usually
          don't want to build the derivation containing the rekeyed secrets on a random remote host.

          The problem is that each derivation will always depend on at least one specific architecture
          (often it's bash), since it requires a builder to create it. Usually the builder will use the
          architecture for which the package is built, which makes sense. Since it is part of the derivation
          inputs, we have to know it in advance to predict where the output will be. If you have multiple
          architectures, then we'd have multiple candidate derivations for the rekeyed secrets, but we want
          a single predictable derivation.

          If you would try to deploy an aarch64-linux system, but are on x86_64-linux without binary
          emulation, then nix would have to build the rekeyed secrets using a remote builder (since the
          derivation then requires aarch64-linux bash). This option will override the pkgs set passed to
          the derivation such that it will use a builder of the specified architecture instead. This way
          you can force it to always require a x86_64-linux bash, thus allowing your local system to build it.

          The "automatic" and nice way would be to set this to builtins.currentSystem, but that would
          also be impure, so unfortunately you have to hardcode this option.
        '';
        default = null;
        example = "x86_64-linux";
      };
      hostPubkey = mkOption {
        type = with types;
          coercedTo path (x: if isPath x then readFile x else x) str;
        description = ''
          The age public key to use as a recipient when rekeying. This either has to be the
          path to an age public key file, or the public key itself in string form.
          HINT: If you want to use a path, make sure to use an actual nix path, so for example
          `./host.pub`, otherwise it will be interpreted as the content and cause errors.
          Alternatively you can use `readFile "/path/to/host.pub"` yourself.

          If you are managing a single host only, you can use `"/etc/ssh/ssh_host_ed25519_key.pub"`
          here to allow the rekey app to directly read your pubkey from your system.

          If you are managing multiple hosts, it's recommended to either store a copy of each
          host's pubkey in your flake and use refer to those here `./secrets/host1-pubkey.pub`,
          or directly set the host's pubkey here by specifying `"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."`.

          Make sure to NEVER use a private key here, as it will end up in the public nix store!
        '';
        default = dummyPubkey;
        example = literalExpression "./secrets/host1.pub";
        #example = "/etc/ssh/ssh_host_ed25519_key.pub";
      };
      masterIdentities = mkOption {
        type = with types; listOf (coercedTo path toString str);
        description = ''
          The list of age identities that will be presented to `rage` when decrypting the stored secrets
          to rekey them for your host(s). If multiple identities are given, they will be tried in-order.

          The recommended options are:

          - Use a split-identity ending in `.pub`, where the private part is not contained (a yubikey identity)
          - Use an absolute path to your key outside of the nix store ("/home/myuser/age-master-key")
          - Or encrypt your age identity and use the extension `.age`. You can encrypt an age identity
            using `rage -p -o privkey.age privkey` which protects it in your store.

          If you are using YubiKeys, you can specify multiple split-identities here and use them interchangeably.
          You will have the option to skip any YubiKeys that are not available to you in that moment.

          Be careful when using paths here, as they will be copied to the nix store. Using
          split-identities is fine, but if you are using plain age identities, make sure that they
          are password protected.
        '';
        default = [ ];
        example = [ ./secrets/my-public-yubikey-identity.txt ];
      };
      agePlugins = mkOption {
        type = types.listOf types.package;
        default = [ rekeyHostPkgs.age-plugin-yubikey ];
        description = ''
          A list of plugins that should be available to rage while rekeying.
          They will be added to the PATH with lowest-priority before rage is invoked,
          meaning if you have the plugin installed on your system, that one is preferred
          in an effort to not break complex setups (e.g. WSL passthrough).
        '';
      };
    };
  };
}
