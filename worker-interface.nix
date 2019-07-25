{ lib }:


with lib;


{ 
  options = {
    services.concourse = {
      worker = with types; {
        name = mkOption {
          type = str;
          description = ''
            The name to set for the worker during registration. 
            If not specified, the hostname will be used.
          '';
        };

        tag = mkOption {
          type = str;
          example = "tag-1,tag-2";
          description = "A tag to set during registration. Can be specified multiple times.";
        };

        team = mkOption {
          type = str;
          default = "";
          description = "The name of the team that this worker will be assigned to.";
        };

        httpProxy = mkOption {
          type = str;
          description = "HTTP proxy endpoint to use for containers.";
        };

        httpsProxy = mkOption {
          type = str;
          description = "HTTPS proxy endpoint to use for containers.";
        };

        # "--no-proxy" option
        proxyBlackList = mkOption {
          type = str;
          description = "Blacklist of addresses to skip the proxy when reaching.";
        };

        ephemeral = mkOption {
          type = bool;
          defualt = false;
          description = "If set, the worker will be immediately removed upon stalling.";
        };

        certsDir = mkOption {
          type = path; 
          default = /var/lib/concourse/certs;
          description = "Directory to use when creating the resource certificates volume.";
        };

        workDir = mkOption {
          type = path;
          default = /var/lib/concourse/worker;
          description = "Directory in which to place container data.";
        };

        bindIp = mkOption {
          type = str;
          default = "127.0.0.1";
          description = "IP address on which to listen for the Garden server.";
        };

        bindPort = mkOption {
          type = str;
          default = "7777";
          description = "Port on which to listen for the Garden server.";
        };

        debugBindIp = mkOption {
          type = str;
          default = "127.0.0.1";
          description = ''
            IP address on which to listen for the pprof debugger endpoints.
          '';
        };

        debugBindPort = mkOption {
          type = str;
          default = "7776";
          description = "Port on which to listen for the pprof debugger endpoints.";
        };

        healthcheckBindIp = mkOption {
          type = str;
          default = "0.0.0.0";
          description = "IP address on which to listen for health checking requests.";
        };

        healthcheckBindPort = mkOption {
          type = str;
          default = "8888";
          description = "Port on which to listen for health checking requests.";
        };

        healthchreckTimeout = mkOption {
          type = str;
          default = "5s";
          description = "HTTP timeout for the full duration of health checking.";
        };

        sweepInterval = mkOption {
          type = str;
          default = "30s";
          description = ''
            Interval on which containers and volumes
            will be garbage collected from the worker.
          '';
        };

        volumeSweeperMaxInFlight = mkOption {
          type = str;
          default = "3";
          description = ''
            Maximum number of volumes which can be swept in parallel.
          '';
        };

        containerSweeperMaxInFlight = mkOption {
          type = str;
          default = "5";
          description = ''
            Maximum number of containers which can be swept in parallel.
          '';
        };

        rebalanceInterval = mkOption {
          type = str;
          description = ''
            Duration after which the registration 
            should be swapped to another random SSH gateway.
          '';
        };

        connectionDrainTimeout = mkOption {
          type = str;
          default = "1h";
          description = ''
            Duration after which a worker should give up
            draining forwarded connections on shutdown.
          '';
        };

        externalGardenUrl = mkOption {
          type = str;
          description = ''
            API endpoint of an externally managed Garden server to use
            instead of running the embedded Garden server.
          '';
        };

        resourceTypes = mkOption {
          type = path;
          default = /var/lib/resource-types;
          description = ''
            Path to directory containing resource types the worker should advertise.
          '';
        };

        logLevel = mkOption {
          type = enum [
            "debug" 
            "info" 
            "error" 
            "fatal" 
          ];
          default = "info";
          description = "Minimum level of logs to see.";
        };

        tsa = {
          tsaHost = mkOption {
            type = str;
            default = "127.0.0.1:2222";
            description = ''
              TSA host to forward the worker through.
              Can be specified multiple times.
            '';
          };

          tsaPublicKey = mkOption {
            type = path;
            description = ''
              File containing a public key to expect from the TSA.
            '';
          };

          tsaWorkerPrivateKey = mkOption {
            type = path;
            description = ''
              File containing the private key to use when authenticating to the TSA.
            '';
          };
        };

        garden = {
          useHoudini = mkOption {
            type = bool;
            default = false;
            description = "Use the insecure Houdini Garden backend.";
          };

          gardenBin = mkOption {
            type = str;
            default = "${concourse}/bin/gdn";
            description = "Path to 'gdn' executable.";
          };

          gardenConfig = mkOption {
            type = lines;
            description = "Path to a config file to use for Garden.";
          };

          gardenDnsProxyEnable = mkOption {
            type = bool;
            default = false;
            description = "Enable proxy DNS server.";
          };
        };

        baggageclaim = {
          logLevel = mkOption {
            type = enum [
              "debug"
              "info"
              "error"
              "fatal"
            ];
            default = "info";
            description = "Minimum level of logs to see.";
          };

          bindIp = mkOption {
            type = str;
            default = "127.0.0.1";
            description = ''
              IP address on which to listen for API traffic.
            '';
          };

          bindPort = mkOption {
            type = str;
            default = "7788";
            description = ''
              Port on which to listen for API traffic.
            '';
          };

          debugBindIp = mkOption {
            type = str;
            default = "127.0.0.1";
            description = ''
              IP address on which to listen for the pprof debugger endpoints.
            '';
          };

          debugBindPort = mkOption {
            type = str;
            default = "7787";
            description = ''
              Port on which to listen for the pprof debugger endpoints.
            '';
          };

          volumes = mkOption {
            type = path;
            description = ''
              Directory in which to place volume data.
            '';
          };

          driver = mkOption {
            type = enum [
              "detect"
              "naive"
              "btrfs"
              "overlay"
            ];
            default = "detect";
            description = ''
              Driver to use for managing volumes.
            '';
          };

          btrfsBin = mkOption {
            type = str;
            default = "btrfs";
            description = "Path to btrfs binary.";
          };

          mkfsBin = mkOption {
            type = str;
            default = "mkfs.btrfs";
            description = "Path to mkfs.btrfs binary";
          };

          overlaysDir = mkOption {
            type = path;
            description = ''
              Path to directory in which to store overlay data.
            '';
          };

          disableUserNamespaces = mkOption {
            type = bool;
            default = false;
            description = ''
              Disable remapping of user/group IDs in unprivileged volumes.
            '';
          };
        };
      };
    };
  };
}
