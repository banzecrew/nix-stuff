{ lib }:


with lib;  


{
  options = {
    services.concourse = {
      web = with types; {
        peerAddress = mkOption {
          type = str;
          default = "127.0.0.1";
          description = ''
            Network address of this web node, reachable by other web nodes. 
            Used for forwarded worker addresses.
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

        bindIp = mkOption {
          type = str;
          default = "0.0.0.0";
          description = "IP address on which to listen for web traffic.";
        };

        bindPort = mkOption {
          type = str;
          default = "8080";
          description = "Port on which to listen for HTTP traffic.";
        };

        tlsBindPort = mkOption {
          type = str;
          description = "Port on which to listen for HTTPS traffic.";
        };

        tlsCert = mkOption {
          type = path;
          description = "File containing an SSL certificate.";
        };

        tlsKey = mkOption {
          type = path;
          description = ''
            File containing an RSA private key, 
            used to encrypt HTTPS traffic.
          '';
        };
        
        externalUrl = mkOption {
          type = str;
          description = "URL used to reach any ATC from the outside world.";
        };

        encryptionKey = mkOption {
          type = str;
          description = ''
            A 16 or 32 length key used to encrypt sensitive information
            before storing it in the database
          '';
        };
         
        oldEncryptionKey = mkOption {
          type = str;
          description = ''
            Encryption key previously used for encrypting sensitive information. 
            If provided without a new key, data is encrypted. 
            If provided with a new key, data is re-encrypted.
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
          default = "8079";
          description = "Port on which to listen for the pprof debugger endpoints.";
        };

        interceptIdleTemiout = mkOption {
          type = str;
          default = "0m";
          description = ''
            Length of time for a intercepted session to be idle before terminating.
          '';
        };

        enableGlobalResources = mkOption {
          type = bool;
          default = false;
          description = ''
            Enable equivalent resources across pipelines and teams
            to share a single version history.
          '';
        };
 
        globalResourceCheckTimeout = mkOption {
          type = str;
          default = "1h";
          description = ''
            Time limit on checking for new versions of resources.
          '';
        };

        resourceCheckingInterval = mkOption {
          type = str;
          default = "1m";
          description = ''
            Interval on which to check for new versions of resources.
          '';
        };

        resourceTypeCheckingInterval = mkOption {
          type = str;
          default = "1m";
          description = ''
            Interval on which to check for new versions of resource types.
          '';
        };

        containerPlacementStrategy = mkOption {
          type = enum [ 
            "volume-locality"
            "random"
            "fewest-build-containers"
          ];
          default = "volume-locality";
          description = ''
            Method by which a worker is selected during container placement.
          '';
        };

        baggageclaimResponseHeaderTimeout = mkOption {
          type = str;
          default = "1m";
          description = ''
            How long to wait for Baggageclaim to send the response header.
          '';
        };

        cliArtifactsDir = mkOption {
          type = path;
          description = ''
            Directory containing downloadable CLI binaries.
          '';
        };

        logDbQueries = mkOption {
          type = bool;
          default = false;
          description = "Log database queries.";
        };
 
        buildTrackerInterval = mkOption {
          type = str;
          default = "10s";
          description = "Interval on which to run build tracking.";
        };

        defaultBuildLogsToRetain = mkOption {
          type = str;
          description = "Default build logs to retain, 0 means all";
        };

        maxBuildLogsToRetain = mkOption {
          type = str;
          description = ''
            Maximum build logs to retain, 0 means not specified.
            Will override values configured in jobs.
          '';
        };

        deafaultDaysToRetainBuildLogs = mkOption {
          type = str;
          description = ''
            Default days to retain build logs.
            0 means unlimited.
          '';
        };

        maxDaysToRetainBuildLogs = mkOption {
          type = str;
          description = ''
            Maximum days to retain build logs, 0 means not specified.
            Will override values configured in jobs.
          '';
        };
 
        defaultTaskCpuLimit = mkOption {
          type = str;
          description = ''
            Default max number of cpu shares per task, 0 means unlimited.
          '';
        };

        defaultTaskMemoryLimit = mkOption {
          type = str;
          description = ''
            Default maximum memory per task, 0 means unlimited.
          '';
        };

        enableBuildAuditing = mkOption {
          type = bool;
          default = true;
          description = ''
            Enable auditing for all api requests connected to builds.
          '';
        };

        enableContainerAuditing = mkOption {
          type = bool;
          default = true;
          description = ''
            Enable auditing for all api requests connected to containers.
          '';
        };

        enableJobAuditing = mkOption {
          type = bool;
          default = true;
          description = ''
            Enable auditing for all api requests connected to jobs.
          '';
        };

        enablePipelineAuditing = mkOption {
          type = bool;
          default = true;
          description = ''
            Enable auditing for all api requests connected to pipelines.
          '';
        };

        enableResourceAuditing = mkOption {
          type = bool;
          default = true;
          description = ''
            Enable auditing for all api requests connected to resources.
          '';
        };

        enableSystemAuditing = mkOption {
          type = bool;
          default = true;
          description = ''
            Enable auditing for all api requests connected to system transactions.
          '';
        };

        enableTeamAuditing = mkOption {
          type = bool;
          default = true;
          description = ''
            Enable auditing for all api requests connected to teams.
          '';
        };

        enableWorkerAuditing = mkOption {
          type = bool;
          default = true;
          description = ''
            Enable auditing for all api requests connected to workers.
          '';
        };

        enableVolumeAuditing = mkOption {
          type = bool;
          default = true;
          description = ''
            Enable auditing for all api requests connected to volumes.
          '';
        };

        tsa = {
          tsaLogLevel = mkOption {
            type = enum [ 
              "debug"
              "info"
              "error"
              "fatal"
            ];
            default = "info";
            description = "Minimum level of logs to see.";
          };

          tsaBindIp = mkOption {
            type = str;
            default = "0.0.0.0";
            description = "IP address on which to listen for SSH.";
          };

          tsaPeerAddress = mkOption {
            type = str;
            default = "127.0.0.1";
            description = ''
              Network address of this web node, reachable by other web nodes.
              Used for forwarded worker addresses.           
            '';
          };
 
          tsaBindPort = mkOption {
            type = str;
            default = "2222";
            description = "Port on which to listen for SSH.";
          };

          tsaDebugBindIp = mkOption {
            type = str;
            default = "127.0.0.1";
            description = ''
              IP address on which to listen for the pprof debugger endpoints.
            '';
          };

          tsaDebugBindPort = mkOption {
            type = str;
            default = "2221";
            description = ''
              Port on which to listen for the pprof debugger endpoints.
            '';
          };

          tsaHostKey = mkOption {
            type = path;
            description = "Path to private key to use for the SSH server.";
          };

          tsaAuthorizedKeys = mkOption {
            type = path;
            description = ''
              Path to file containing keys to authorize, 
              in SSH authorized_keys format 
            '';
          };

          tsaTeamAuthorizedKeys = mkOption {
            type = str;
            description = ''
              Path to file containing keys to authorize,
              in SSH authorized_keys format (one public key per line).
            '';
          };
 
          tsaAtcUrl = mkOption {
            type = str;
            description = ''
              ATC API endpoints to which workers will be registered.
            '';
          }; 

          tsaSessionSigningKey = mkOption {
            type = string;
            description = ''
              Path to private key to use when signing tokens
              in reqests to the ATC during registration.
            '';
          };

          tsaHeartBeatInterval = mkOption {
            type = str;
            default = "30s";
            description = "interval on which to heartbeat workers to the ATC";
          };      
        };

        encrypt = {
          enableLetsEncrypt = mkOption {
            type = bool;
            default = false;
            description = ''
              Automatically configure TLS certificates via Let's Encrypt/ACME.
            '';
          };

          acmeUrl = mkOption {
            type = str;
            default = "https://acme-v01.api.letsencrypt.org/directory";
            description = ''
              URL of the ACME CA directory endpoint.
            '';
          };
        };

        postgresql = {
          pgHost = mkOption {
            type = str;
            default = "127.0.0.1";
            description = "The host to connect to.";
          };

          pgPort = mkOption {
            type = str;
            default = "5432";
            description = "The port to connect to.";
          };

          pgSocket = mkOption {
            type = path;
            default = /var/run/postgresql;
            description = "Path to a UNIX domain socket to connect to.";
          };

          pgUser = mkOption {
            type = str;
            default = "concourse";
            description = "The user to sign in as.";
          };

          pgPassword = mkOption {
            type = str;
            default = "concourse";
            description = "The user's password.";
          };

          pgSslMode = mkOption {
            type = enum [
              "disable"
              "require"
              "verify-ca"
              "verify-full"
            ];
            default = "disable";
            description = "Whether or not to use SSL.";
          };

          pgCaCert = mkOption {
            type = path;
            description = ''
              CA cert file location, to verify when connecting with SSL.
            '';
          };

          pgClientCert = mkOption {
            type = path;
            description = "Client cert file location.";
          };      

          pgClientKey = mkOption {
            type = path;
            description = "Client key file location.";
          };

          pgConnectTimeout = mkOption {
            type = str;
            default = "5m";
            description = ''
              Dialing timeout. (0 means wait indefinitely)
            '';
          };

          pgDatabase = mkOption {
            type = str;
            default = "atc";
            description = "The name of the database to use.";
          };
        };

        credentials = {
          secretRetryAttempts = mkOption {
            type = str;
            default = "5";
            description = ''
              The number of attempts secret will be retried to be fetched,
              in case a retryable error happens.
            '';
          };

          secretRetryInterval = mkOption {
            type = str;
            default = "1s";
            description = ''
              The interval between secret retry retrieval attempts.
            '';
          };

          secretCacheEnabled = mkEnable {
            type = bool;
            default = false;
            description = ''
              Enable in-memory cache for secrets.
            '';
          };

          secretCacheDuration = mkEnable {
            type = str;
            default = "1m";
            description = ''
              If the cache is enabled, secret values will be cached for not longer
              than this duration (it can be less, if underlying secret lease time is smaller)
            '';
          };

          secretCachePurgeInterval = mkEnable {
            type = str;
            default = "10m";
            description = ''
              If the cache is enabled, expired items will be removed on this internal.
            '';
          };

          credhub = {
            url = mkOption {
              tpye = str;
              description = ''
                CredHub server address used to access secrets.
              '';
            };

            pathPrefix = mkOption {
              type = str;
              default = "/concourse";
              description = ''
                Paths to PEM-encoded CA cert files to use to verify the CredHub server SSL cert.
              '';
            };

            clientCert = mkOption {
              type = str;
              description = ''
                Path to the client certificate for mutual TLS authorization.
              '';
            };

            clientKey = mkOption {
              type = str;
              description = ''
                Path to the client private key for mutual TLS authorization.
              '';
            };

            insecureSkipVerify = {
              type = bool;
              default = false;
              description = ''
                Enable insecure SSL verification.
              '';
            };

            clientId = mkOption {
              type = str;
              description = ''
                Client ID for CredHub authorization.
              '';
            };

            clientSecret = mkOption {
              type = str;
              description = ''
                Client secret for CredHub authorization.
              '';
            };
          };

          kubernetes = {
            inCluster = mkOption {
              type = bool;
              default = false;
              description = ''
                Enables the in-cluster client.
              '';
            };

            configPath = mkOption {
              type = path;
              description = ''
                Path to Kubernetes config when running ATC outside Kubernetes.
              '';
            };

            namespacePrefix = mkOption {
              type = str;
              default = "concourse-";
              description = ''
                Prefix to use for Kubernetes namespaces
                under which secrets will be looked up.
              '';
            };
          };

          awsSecretsCredManagement = {
            accessKey = mkOption {
              type = lines;
              description = ''
                AWS Access key ID.
              '';
            };

            secretkey = mkOption {
              type = lines;
              description = ''
                AWS Secret Access Key.
              '';
            };

            sessionToken = mkOption {
              type = lines;
              description = ''
                AWS Session Token.
              '';
            };

            region = mkOption {
              type = lines;
              description = ''
                AWS region to send requests to.
              '';
            };

            pipelineSecretTemplate = mkOption {
              type = str;
              default = "/concourse/{{.Team}}/{{.Pipeline}}/{{.Secret}}";
              description = ''
                AWS Secrets Manager secret identifier template
                used for pipeline specific parameter.
              '';
            };

            teamSecretTemplate = mkOption {
              type = str;
              default = "/concourse/{{.Team}}/{{.Secret}}";
              description = ''
                AWS Secrets Manager secret identifier template
                used for team specific parameter.
              '';
            };
          };

          awsSsmCredManagement = {
            accessKey = mkOption {
              type = lines;
              description = ''
                AWS Access key ID.
              '';
            };

            secretKey = mkOption {
              type = lines;
              description = ''
                AWS Secret Access Key.
              '';
            };

            sessionToken = mkOption {
              type = lines;
              description = ''
                AWS Session Token.
              '';
            };

            region = mkOption {
              type = str;
              description = ''
                AWS region to send requests to.
              '';
            };

            pipelineSecretTemplate = mkOption {
              type = str;
              default = "/concourse/{{.Team}}/{{.Pipeline}}/{{.Secret}})";
              description = ''
                AWS SSM parameter name template
                used for pipeline specific parameter.
              '';
            };

            teamSecretPipeline = mkOption {
              type = str;
              default = "/concourse/{{.Team}}/{{.Secret}}";
              description = ''
                AWS SSM parameter name template
                used for team specific parameter.
              '';
            };
          };

          vault = {
            url = mkOption {
              type = str;
              description = ''
                Vault server address used to access secrets.
              '';
            };

            pathPrefix = mkOption {
              type = str;
              default = "/concourse";
              description = ''
                Path under which to namespace credential lookup.
              '';
            };

            sharedPath = mkOption {
              type = str;
              description = ''
                Path under which to lookup shared credentials.
              '';
            };

            caCert = mkOption {
              type = path;
              description = ''
                Path to a PEM-encoded CA cert file to use
                to verify the vault server SSL cert.
              '';
            };

            caPath = mkOption {
              type = path;
              description = ''
                Path to a directory of PEM-encoded CA cert files
                to verify the vault server SSL cert.
              '';
            };

            clientCert = mkOption {
              type = path;
              description = ''
                Path to the client certificate for Vault authorization.
              '';
            };

            clientKey = mkOption {
              type = path;
              description = ''
                Path to the client private key for Vault authorization.
              '';
            };

            serverName = mkOption {
              type = str;
              description = ''
                If set, is used to set the SNI host when connecting via TLS.
              '';
            };

            insecureSkipVerify = mkOption {
              type = bool;
              default = false;
              description = ''
                Enable insecure SSL verification.
              '';
            };

            clientToken = mkOption {
              type = lines;
              description = ''
                Client token for accessing secrets within the Vault server.
              '';
            };

            authBackend = mkOption {
              type = str;
              description = ''
                Auth backend to use for logging in to Vault.
              '';
            };

            authBackendMaxTtl = mkOption {
              type = str;
              description = ''
                Time after which to force a re-login.
                If not set, the token will just be continuously renewed.
              '';
            };

            retryMax = mkOption {
              type = str;
              default = "5m";
              description = ''
                The maximum time between retrieswhen logging in or re-authing a secret.
              '';
            };

            retryInitial = mkOption {
              type = str;
              default = "1s";
              description = ''
                The initial time between retries when logging in or re-authing a secret.
              '';
            };

            authParam = mkOption {
              type = envVar;
              example = "var1:val1,var2:val2";
              description = ''
                Parameter to pass when logging in via the backend.
                Can be specified multiple times.
              '';
            };
          };
        };

        devOptions = {
          noop = mkOption {
            type = bool;
            default = false;
            description = ''
              Don't actually do any automatic scheduling or checking.
            '';
          };
        };

        staticWorker = {
          workerGardenUrl = mkOption {
            type = str;
            description = ''
              A Garden API endpoint to register as a worker.
            '';
          };

          workerBaggageclaimUrl = mkOption {
            type = str;
              description = ''
                A Baggageclaim API endpoint to register with the worker.
              '';
            };

            workerResource = mkOption {
              type = envVar;
              example = "var1:val1,var2:val2";
            description = ''
                A resource type to advertise for the worker.
              Can be specified multiple times.
            '';
            };
        };

        metrics = {
          hostName = mkOption {
            type = str;
            description = ''
              Host string to attach to emitted metrics.
            '';
          };

          attribute = mkOption {
            type = envVar;
            example = "var1:val1,var2:val2";
            description = ''
              A key-value attribute to attach to emitted metrics.
              Can be specified multiple times.
            '';
          };

          captureErrorMetrics = mkOption {
            type = bool;
            default = false;
            description = ''
              Enable capturing of error log metrics.
            '';
          };

          dataDog = {
            agentHost = mkOption {
              type = str;
              description = ''
                Datadog agent host to expose dogstatsd metrics.
              '';
            };

            agentPort = mkOption {
              type = str;
              description = ''
                Datadog agent port to expose dogstatsd metrics.
              '';
            };

            prefix = mkOption {
              type = str;
              description = ''
                Prefix for all metrics to easily find them in Datadog.
              '';
            };
          };

          influxDb = {
            url = mkOption {
              type = str;
              description = ''
                InfluxDB server address to emit points to.
              '';
            };

            database = mkOption {
              type = str;
              description = ''
                InfluxDB database to write points to.
              '';
            };

            username = mkOption {
              type = str;
              description = ''
                InfluxDB server username.
              '';
            };

            password = mkOption {
              type = str;
              description = ''
                InfluxDB server password.
              '';
            };

            insecureSkipVerify = mkOption {
              type = bool;
              default = false;
              description = ''
                Skip SSL verification when emitting to InfluxDB.
              '';
            };
          };

          lager = {
            emitToLogs = mkOption {
              type = bool;
              default = false;
              description = ''
                Dummy emitter that will just spit the metrics
                out in to the logs at DEBUG level.
              '';
            };
          };

          newRelic = {
            accoutId = mkOption {
              type = str;
              description = ''
                New Relic Account ID.
              '';
            };

            apiKey = mkOption {
              type = str;
              description = ''
                New Relic Insights API Key.
              '';
            };

            servicePrefix = mkOption {
              type = str;
              description = ''
                An optional prefix for emitted New Relic events.
              '';
            };
          };

          prometheus = {
            bindIp = mkOption {
              type = str;
              description = ''
                IP to listen on to expose Prometheus metrics.
              '';
            };

            bindPort = mkOption {
              type = str;
              description = ''
                Port to listen on to expose Prometheus metrics.
              '';
            };
          };

          riemann = {
            host = mkOption {
              type = str;
              description = ''
                Riemann server address to emit metrics to.
              '';
            };

            port = mkOption {
              type = str;
              description = ''
                Port of the Riemann server to emit metrics to.
              '';
            };

            servicePrefix = mkOption {
              type = str;
              description = ''
                An optional prefix for emitted Riemann services.
              '';
            };

            tag = mkOption {
              type = str;
              example = "tag1,tag2,tag3";
              description = ''
                Tag to attach to emitted metrics.
                Can be specified multiple times.
              '';
            };
          };
        };

        webServer = {
          xFrameOptions = mkOption {
            type = str;
            default = "deny";
            description = ''
              The value to set for X-Frame-Options.
            '';
          };

          clusterName = mkOption {
            type = str;
            description = ''
              A name for this Concourse cluster,
              to be displayed on the dashboard page.
            '';
          };
        };

        garbageCollection = {
          interval = mkOption {
            type = str;
            default = "30s";
            description = ''
              Interval on which to perform garbage collection.
            '';
          };

          oneOffGracePeriod = mkOption {
            type = str;
            default = "5m";
            description = ''
              Period after which one-off build containers will be garbage-collected.
            '';
          };

          missingGracePeriod = mkOption {
            type = str;
            default = "5m";
            description = ''
              Period after which to reap containers and volumes
              that were created but went missing from the worker.
            '';
          };
        };

        syslogDrainerConf = {
          hostName = mkOption {
            type = str;
            default = "atc-syslog-drainer";
            description = ''
              Client hostname with which the build logs
              will be sent to the syslog server.
            '';
          };

          address = mkOption {
            type = str;
            example = "0.0.0.0:514";
            description = ''
              Remote syslog server address with port.
            '';
          };

          transport = mkOption {
            type = str;
            example = "tcp";
            description = ''
              Transport protocol for syslog messages
              (Currently supporting tcp, udp & tls).
            '';
          };

          drainInterval = mkOption {
            type = str;
            default = "30s";
            description = ''
              Interval over which checking is done for new build logs
              to send to syslog server
              (duration measurement units are s/m/h; eg. 30s/30m/1h).
            '';
          };

          caCert = mkOption {
            type = listOf path;
            description = ''
              Paths to PEM-encoded CA cert files
              to use to verify the Syslog server SSL cert.
            '';
          };
        };

        authentication = {
          cookieSecure = mkOption {
            type = bool;
            default = false;
            description = ''
              Force sending secure flag on http cookies.
            '';
          };

          authDuration = mkOption {
            type = str;
            default = "24h";
            description = ''
              Length of time for which tokens are valid.
              Afterwards, users will have to log back in.
            '';
          };

          sessionSignKey = mkOption {
            type = path;
            description = ''
              File containing an RSA private key, used to sign auth tokens.
            '';
          };

          addLocalUser = mkOption {
            type = str;
            example = "user1:pass1,user2:pass2";
            description = ''
              List of username:password combinations for all your local users.
              The password can be bcrypted - if so,
              it must have a minimum cost of 10.
            '';
          };

          mainTeamLocalUser = mkOption {
            type = str;
            example = "user1,user2";
            description = ''
              List of whitelisted local concourse users.
              These are the users you've added at web startup 
              with the "addLocalUser" option.
            '';
          };

          mainTeamConfig = mkOption {
            type = path;
            description = ''
              Configuration file for specifying team params.
            '';
          };

          bitbucketCloud = {
            user = mkOption {
              type = str;
              example = "user1,user2";
              description = ''
                List of whitelisted Bitbucket Cloud users.
              '';
            };

            team = mkOption {
              type = str;
              example = "team1,team2";
              description = ''
                List of whitelisted Bitbucket Cloud teams.
              '';
            };

            clientId = mkOption {
              type = str;
              description = "(Required) Client ID.";
            };

            clientSecret = mkOption {
              type = str;
              description = "(Required) Client secret";
            };
          };

          cloudFoundry = {
            user = mkOption {
              types = lines;
              example = "user1,user2";
              description = ''
                List of whitelisted CloudFoundry users.
              '';
            };

            orgNames = mkOption {
              type = lines;
              example = "org1,org2";
              description = ''
                List of whitelisted CloudFoundry orgs.
              '';
            };

            space = mkOption {
              type = lines;
              example = ''
                orgName1:spaceName1,
                orgName2:spaceName2
              '';
              description = ''
                List of whitelisted CloudFoundry spaces.
              '';
            };

            spaceGuid = mkOption {
              type = lines;
              example = "guid1,guid2";
              description = ''
                !(Deprecated)! 
                List of whitelisted CloudFoundry space guids.
              '';
            };

            clientId = mkOption {
              type = str;
              description = "(Required) Client id";
            };

            clientSecret = mkOption {
              type = str;
              description = ''
                (Required) Client secret.
              '';
            };

            apiUrl = mkOption {
              type = str;
              description = ''
                (Required) The base API URL of your CF deployment.
                It will use this information to discover information
                about the authentication provider.
              '';
            };

            caCert = mkOption {
              type = lines;
              description = "CA Certificate";
            };

            skipSslValidation = mkOption {
              type = bool;
              default = false;
              description = "Skip SSL validation.";
            };
          };

          github = {
            user = mkOption {
              type = lines;
              example = "user1,user2";
              description = ''
                List of whitelisted GitHub users.
              '';
            };

            orgName = mkOption {
              type = lines;
              example = "org1,org2";
              description = ''
                List of whitelisted GitHub orgs.
              '';
            };

            team = mkOption {
              type = lines;
              example = "org1:team1,org2:team2";
              description = ''
                List of whitelisted GitHub teams.
              '';
            };

            clientId = mkOption {
              type = str;
              description = "(Required) Client id.";
            };

            clientSecret = mkOption {
              type = str;
              description = "(Required) Client secret.";
            };

            host = mkOption {
              type = str;
              description = ''
                Hostname of GitHub Enterprise deployment
                (No scheme, No trailing slash).
              '';
            };

            caCert = mkOption {
              type = lines;
              description = ''
                CA certificate of GitHub Enterprise deployment.
              '';
            };
          };

          gitlab = {
            user = mkOption {
              type = lines;
              example = "user1, user2";
              description = ''
                List of whitelisted GitLab users.
              '';
            };

            group = mkOption {
              type = str;
              example = "group1, group2";
              description = ''
                List of whitelisted GitLab groups.
              '';
            };

            clientId = mkOption {
              type = str;
              description = "(Required) Client id.";
            };

            clientSecret = mkOption {
              type = str;
              description = "(Required) Client secret.";
            };

            host = mkOption {
              type = str;
              description = ''
                Hostname of Gitlab Enterprise deployment
                (Include scheme, No trailing slash).
            '';
            };
          };

          ldap = {
            user = mkOption {
              type = lines;
              example = "user1, user2";
              description = ''
                List of whitelisted LDAP users.
              '';
            };

            group = mkOption {
              type = lines;
              example = "group1, group2";
              description = ''
                List of whitelisted LDAP groups.
              '';
            };

            displayName = mkOption {
              type = str;
              description = ''
                The auth provider name displayed to users on the login page.
              '';
            };

            host = mkOption {
              type = str;
              description = ''
                (Required) The host and optional port of the LDAP server.
                If port isn't supplied, it will be guessed based on the TLS
                configuration. 389 or 636.
              '';
            };

            bindDn = mkOption {
              type = str;
              description = ''
                (Required) Bind DN for searching LDAP users and groups.
                Typically this is a read-only user.
              '';
            };

            bindPw = mkOption {
              type = str;
              description = ''
                (Required) Bind Password for the user specified by 'bind-dn'.
              '';
            };

            insecureNoSsl = mkOption {
              type = str;
              description = ''
                Required if LDAP host does not use TLS.
              '';
            };

            insecureSkipVerify = mkOption {
              type = str;
              description = ''
                Skip certificate verification.
              '';
            };

            startTls = mkOption {
              type = str;
              description = ''
                Start on insecure port, then negotiate TLS.
              '';
            };

            caCert = mkOption {
              type = str;
              description = "CA certificate.";
            };

            userSearchBaseDn = mkOption {
              type = str;
              example = "cn=users,dc=example,dc=com";
              description = ''
                BaseDN to start the search from.
              '';
            };

            userSearchFilter = mkOption {
              type = str;
              example = "(objectClass=person)";
              description = ''
                Optional filter to apply when searching the directory.
              '';
            };

            userSearchUsername = mkOption {
              type = str;
              description = ''
                Attribute to match against the inputted username.
                This will be translated and combined 
                with the other filter as '(<attr>=<username>)';
              '';
            };

            userSearchScope = mkOption {
              type = str;
              default = "sub";
              description = ''
                Can either be: 'sub' - search the whole sub tree
                or 'one' - only search one level.
              '';
            };

            userSearchIdAttr = mkOption {
              type = str;
              default = "uid";
              description = ''
                A mapping of attributes on the user entry to claims.
              '';
            };

            userSearchEmailAttr = mkOption {
              type = str;
              default = "mail";
              description = ''
                A mapping of attributes on the user entry to claims.
              '';
            };

            userSearchNameAttr = mkOption {
              type = str;
              description = ''
                A mapping of attributes on the user entry to claims.
              '';
            };

            groupSearchBaseDn = mkOption {
              type = str;
              example = "cn=groups,dc=example,dc=com";
              description = ''
                BaseDN to start the search from.
              '';
            };

            groupSearchFilter = mkOption {
              type = str;
              example = "(objectClass=posixGroup)";
              description = ''
                Optional filter to apply when searching the directory.
              '';
            };

            groupSearchScope = mkOption {
              type = str;
              default = "sub";
              description = ''
                Can either be: 'sub' - search the whole sub tree
                or 'one' - only search one level.
              '';
            };

            groupSearchUserAttr = mkOption {
              type = str;
              description = ''
                Adds an additional requirement to the filter that an attribute
                in the group match the user's attribute value.
                The exact filter being added is: (<groupAttr>=<userAttr value>).
              '';
            };

            groupSearchGroupAttr = mkOption {
              type = str;
              description = ''
                Adds an additional requirement to the filter that an attribute
                in the group match the user's attribute value.
                The exact filter being added is: (<groupAttr>=<userAttr value>).
              '';
            };

            groupSearchNameAttr = mkOption {
              type = str;
              description = ''
                The attribute of the group that represents its name.
              '';
            };
          };

          oauth2 = {
            user = mkOption {
              type = str;
              example = "user1,user2";
              description = ''
                List of whitelisted OAuth2 users.
              '';
            };

            group = mkOption {
              type = str;
              example = "group1,group2";
              description = ''
                List of whitelisted OAuth2 groups.
              '';
            };

            displayName = mkOption {
              type = str;
              description = ''
                The auth provider name displayed to users on the login page.
              '';
            };

            clientId = mkOption {
              type = str;
              description = "(Required) Client id";
            };

            clientSecret = mkOption {
              type = str;
              description = "(Required) Client secret.";
            };

            authUrl = mkOption {
              type = str;
              description = "(Required) Authorization URL.";
            };

            tokenUrl = mkOption {
              type = str;
              description = "(Required) Token URL.";
            };

            userinfoUrl = mkOption {
              type = str;
              description = "(Required) UserInfo URL.";
            };

            scope = mkOption {
              type = str;
              description = ''
                Any additional scopes that need to be requested during authorization.
              '';
            };

            groupsKey = mkOption {
              type = str;
              default = "groups";
              description = ''
                The groups key indicates which claim
                to use to map external groups to Concourse teams.
              '';
            };

            userIdKey = mkOption {
              type = str;
              default = "user_id";
              description = ''
                The user id key indicates which claim
                to use to map an external user id to a Concourse user id.
              '';
            };

            usernameKey = mkOption {
              type = str;
              default = "user_name";
              description = ''
                The user name key indicates which claim
                to use to map an external user name to a Concourse user name.
              '';
            };

            caCert = mkOption {
              type = str;
              description = "CA Certificate";
            };

            skipSslValidation = mkOption {
              type = bool;
              default = false;
              description = "Skip SSL validation";
            };
          };
        };

        oidc = {
          user = mkOption {
            type = str;
            example = "user1,user2";
            description = ''
              List of whitelisted OIDC users.
            '';
          };

          group = mkOption {
            type = str;
            example = "group1,group2";
            description = ''
              List of whitelisted OIDC groups.
            '';
          };

          displayName = mkOption {
            type = str;
            description = '' 
              The auth provider name displayed to users on the login page.
            '';
          };

          issuer = mkOption {
            type = str;
            description = ''
              (Required) An OIDC issuer URL that will be used
              to discover provider configuration using the .well-known/openid-configuration
            '';
          };

          clientId = mkOption {
            type = str;
            description = "(Required) Client id";
          };

          clientSecret = mkOption {
            type = str;
            description = "(Required) Client secret";
          };

          scope = mkOption {
            type = str;
            description = ''
              Any additional scopes that need to be requested during authorization.
            '';
          };

          groupsKey = mkOption {
            type = str;
            default = "groups";
            description = ''
              The groups key indicates which claim
              to use to map external groups to Concourse teams.
            '';
          };

          usernameKey = mkOption {
            type = str;
            default = "username";
            description = ''
              The user name key indicates which claim
              to use to map an external user name to a Concourse user name.
            '';
          };

          hostedDomains = mkOption {
            type = str;
            description = ''
              List of whitelisted domains when using Google,
              only users from a listed domain will be allowed to log in.
            '';
          };

          caCert = mkOption {
            type = str;
            description = "CA Certificate";
          };

          skipSslValidation = mkOption {
            type = bool;
            default = false;
            description = "Skip SSL validation";
          };
        }; 
      };
    };
  };
}
