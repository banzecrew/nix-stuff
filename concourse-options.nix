{ config, lib, pkgs, ... }:


with lib;


let
  cfg = config.services.concourse;
  e = callPackage ./environment.nix { };

in


{
  options = {
    services.concourse = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = "Enable/disable Concourse CI";
      };

      mode = mkOption {
        type = types.enum [ "web" "worker" "quickstart" ];
        default = "web";
        description = "Sets Concourse working mode.";
      };

      package = mkOption {
        type = types.package;
        default = pkgs.concourse;
        description = "Package to use.";
      };
    };
  };

  config = mkIf cfg.enable {

    environment.systemPackages = [ cfg.package ];

    systemd.services.concourse = {
      description = "Concourse service daemon";
      wantedBy = ["multi-user.target"];
      
      requires = [(
        if cfg.mode == "worker" then ""
        else "postgresql.service"
      )];

      after = [
        "networking.target"
      ] ++ requires;

      environment = {

      } // (if cfg.mode == "web"
            then
              mapAttrs' (n: v: nameValuePair "CONCOURSE_${n}" (toString v)) e.envOptions.web
            else if cfg.mode == "worker"
            then
              mapAttrs' (n: v: nameValuePair "CONCOURSE_${n}" (toString v)) e.envOptions.worker
            else if cfg.mode == "quickstart"
            then
              (mapAttrs' (n: v: nameValuePair "CONCOURSE_WORKER_${n}" (toString v)) (e.envOptions.worker)) // e.envOptions.web
            else 
               ""
           );

      script = ''
        exec ${cfg.package}/bin/concourse ${cfg.mode}
      '';
    };
  };
}
