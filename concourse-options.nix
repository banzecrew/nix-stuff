{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.concourse;
  mode = cfg.mode;

  envOptions = {
    web = {
      PEER_ADDRESS = cfg.web.peerAddress;
      LOG_LEVEL = cfg.web.logLevel;
      BIND_IP = cfg.web.bindIp;
      BIND_PORT = cfg.web.bindPort;
      TLS_BIND_PORT = cfg.web.tlsBindPort;
      TLS_CERT = cfg.web.tlsCert;
      TLS_KEY = cfg.web.tlsKey;
      EXTERNAL_URL = cfg.web.externalUrl;
      ENCRYPTION_KEY = cfg.web.encryptionKey;
      OLD_ENCRYPTION_KEY = cfg.web.oldEncryptionKey;
      DEBUG_BIND_IP = cfg.web.debugBindIp;
      DEBUG_BIND_PORT = cfg.web.debugBindPort;
      INTERCEPT_IDLE_TIMEOUT = cfg.web.interceptIdleTemiout;
      ENABLE_GLOBAL_RESOURCES = boolToString cfg.web.enableGlobalResources;
      GLOBAL_RESOURCE_CHECK_TIMEOUT = cfg.web.globalResourceCheckTimeout;
      RESOURCE_CHECKING_INTERVAL = cfg.web.resourceCheckingInterval;
      RESOURCE_TYPE_CHECKING_INTERVAL = cfg.web.resourceTypeCheckingInterval;
      CONTAINER_PLACEMENT_STRATEGY = cfg.web.containerPlacementStrategy;
      BAGGAGECLAIM_RESPONSE_HEADER_TIMEOUT = cfg.web.baggageclaimResponseHeaderTimeout;
      CLI_ARTIFACTS_DIR = cfg.web.cliArtifactsDir;
      LOG_DB_QUERIES = boolToString cfg.web.logDbQueries;
      BUILD_TRACKER_INTERVAL = cfg.web.buildTrackerInterval;
      DEFAULT_BUILD_LOGS_TO_RETAIN = cfg.web.defaultBuildLogsToRetain;
      MAX_BUILD_LOGS_TO_RETAIN = cfg.web.maxBuildLogsToRetain;
      DEFAULT_DAYS_TO_RETAIN_BUILD_LOGS = cfg.web.deafaultDaysToRetainBuildLogs;
      MAX_DAYS_TO_RETAIN_BUILD_LOGS = cfg.web.maxDaysToRetainBuildLogs;
      DEFAULT_TASK_CPU_LIMIT = cfg.web.defaultTaskCpuLimit;
      DEFAULT_TASK_MEMORY_LIMIT = cfg.web.defaultTaskMemoryLimit;
      ENABLE_BUILD_AUDITING = boolToString cfg.web.enableBuildAuditing;
      ENABLE_CONTAINER_AUDITING = bloolToString cfg.web.enableContainerAuditing;
      ENABLE_JOB_AUDITING = boolToString cfg.web.enableJobAuditing;
      ENABLE_PIPELINE_AUDITING = boolToString cfg.web.enablePipelineAuditing;
      ENABLE_RESOURCE_AUDITING = boolToString cfg.web.enableResourceAuditing;
      ENABLE_SYSTEM_AUDITING = boolToString cfg.web.enableSystemAuditing;
      ENABLE_TEAM_AUDITING = boolToString cfg.web.enableTeamAuditing;
      ENABLE_WORKER_AUDITING = boolToString cfg.web.enableWorkerAuditing;
      ENABLE_VOLUME_AUDITING = boolToString cfg.web.enableVolumeAuditing;

      ENABLE_LETS_ENCRYPT = boolToString cfg.web.encrypt.enableLetsEncrypt;
      LETS_ENCRYPT_ACME_URL = cfg.web.encrypt.letsEncryptAcmeUrl;
      
      POSTGRES_HOST = cfg.web.postgresql.pgHost;
      POSTGRES_PORT = cfg.web.postgresql.pgPort;
      POSTGRES_SOCKET = cfg.web.postgresql.pgSocket;
      POSTGRES_USER = cfg.web.postgresql.pgUser;
      POSTGRES_PASSWORD = cfg.web.postgresql.pgPassword;
      POSTGRES_SSLMODE = cfg.web.postgresql.pgSslMode;
      POSTGRES_CA_CERT = cfg.web.postgresql.pgCaCert;
      POSTGRES_CLIENT_CERT = cfg.web.postgresql.pgClientCert;
      POSTGRES_CLIENT_KEY = cfg.web.postgresql.pgClientKey;
      POSTGRES_CONNECT_TIMEOUT = cfg.web.postgresql.pgConnectTimeout;
      POSTGRES_DATABASE = cfg.web.postgresql.pgDatabase;
      
      SECRET_RETRY_ATTEMPTS = cfg.web.secret.secretRetryAttempts;
      SECRET_RETRY_INTERVAL = cfg.web.secretRetryInterval;
      SECRET_CACHE_ENABLED = boolToString cfg.web.secretCacheEnabled;
      SECRET_CACHE_DURATION = cfg.web.secretCacheDuration;
      SECRET_CACHE_PURGE_INTERVAL = secretCachePurgeInterval;

      CREDHUB_URL = cfg.web.credentials.credhub.url;
      CREDHUB_PATH_PREFIX = cfg.web.credentials.credhub.pathPrefix;
      CREDHUB_CA_CERT = cfg.web.credentials.credhub.clientCert;
      CREDHUB_CLIENT_CERT = cfg.web.credentials.credhub.clientCert;
      CREDHUB_CLIENT_KEY = cfg.web.credentials.credhub.clientKey;
      CREDHUB_INSECURE_SKIP_VERIFY = boolToString cfg.web.credentials.credhub.insecureSkipVerify;
      CREDHUB_CLIENT_ID = cfg.web.credentials.credhub.clientId;
      CREDHUB_CLIENT_SECRET = cfg.web.credentials.credhub.clientSecret;

      KUBERNETES_IN_CLUSTER = boolToString cfg.web.credentials.kubernetes.inCluster;
      KUBERNETES_CONFIG_PATH = cfg.web.credentials.kubernetes.configPath;
      KUBERNETES_NAMESPACE_PREFIX = cfg.web.credentials.kubernetes.namespacePrefix;

      AWS_SECRETSMANAGER_ACCESS_KEY = cfg.web.credentials.awsSecretsCredManagement.accessKey;
      AWS_SECRETSMANAGER_SECRET_KEY = cfg.web.credentials.awsSecretsCredManagement.secretKey;
      AWS_SECRETSMANAGER_SESSION_TOKEN = cfg.web.credentials.awsSecretsCredManagement.sessionToken;
      AWS_SECRETSMANAGER_REGION = cfg.web.credentials.awsSecretsCredManagement.region;
      AWS_SECRETSMANAGER_PIPELINE_SECRET_TEMPLATE = cfg.web.credentials.awsSecretsCredManagement.pipelineSecretTemplate;
      AWS_SECRETSMANAGER_TEAM_SECRET_TEMPLATE = cfg.web.credentials.awsSecretsCredManagement.teamSecretTemplate;

      AWS_SSM_ACCESS_KEY = cfg.web.credentials.awsSsmCredManagement.accessKey;
      AWS_SSM_SECRET_KEY = cfg.web.credentials.awsSsmCredManagement.secretKey;
      AWS_SSM_SESSION_TOKEN = cfg.web.credentials.awsSsmCredManagement.sessionToken;
      AWS_SSM_REGION = cfg.web.credentials.awsSsmCredManagement.region;
      AWS_SSM_PIPELINE_SECRET_TEMPLATE = cfg.web.credentials.awsSsmCredManagement.pipelineSecretTemplate;
      AWS_SSM_TEAM_SECRET_TEMPLATE = cfg.web.credentials.awsSsmCredManagement.teamSecretTemplate;

      VAULT_URL = cfg.web.credentials.vault.url;
      VAULT_PATH_PREFIX = cfg.web.credentials.vault.pathPrefix;
      VAULT_SHARED_PATH = cfg.web.credentials.vault.sharedPath;
      VAULT_CA_CERT = cfg.web.credentials.vault.caCert;
      VAULT_CA_PATH = cfg.web.credentials.vault.caPath;
      VAULT_CLIENT_CERT = cfg.web.credentials.vault.clientCert;
      VAULT_CLIENT_KEY = cfg.web.credentials.vault.clientKey;
      VAULT_SERVER_NAME = cfg.web.credentials.vault.serverName;
      VAULT_INSECURE_SKIP_VERIFY = boolToString cfg.web.credentials.vault.insecureSkipVerify;
      VAULT_CLIENT_TOKEN = cfg.web.credentials.vault.clientToken;
      VAULT_AUTH_BACKEND = cfg.web.credentials.vault.authBackend;
      VAULT_AUTH_BACKEND_MAX_TTL = cfg.web.credentials.vault.authBackendMaxTtl;
      VAULT_RETRY_MAX = cfg.web.credentials.vault.retryMax;
      VAULT_RETRY_INITIAL = cfg.web.credentials.vault.retryInitial;
      VAULT_AUTH_PARAM = cfg.web.credentials.vault.authParam;

      NOOP = boolToString cfg.web.devOptions.noop;

      WORKER_GARDEN_URL = cfg.web.staticWorker.workerGardenUrl;
      WORKER_BAGGAGECLAIM_URL = cfg.web.staticWorker.workerBaggageclaimUrl;
      WORKER_RESOURCE = cfg.web.staticWorker.workerResource;

      METRICS_HOST_NAME = cfg.web.metrics.hostName;
      METRICS_ATTRIBUTE = cfg.web.metrics.attributes;
      CAPTURE_ERROR_METRICS = boolToString cfg.web.metrics.captureErrorMetrics;

      DATADOG_AGENT_HOST = cfg.web.metrics.dataDog.agentHost;
      DATADOG_AGENT_PORT = cfg.web.metrics.agentPort;
      DATADOG_PREFIX = cfg.web.metrics.prefix;

      INFLUXDB_URL = cfg.web.metrics.influxDb.url;
      INFLUXDB_DATABASE = cfg.web.metrics.influxDb.database;
      INFLUXDB_USERNAME = cfg.web.metrics.influxDb.username;
      INFLUXDB_PASSWORD = cfg.web.metrics.influxDb.password;
      INFLUXDB_INSECURE_SKIP_VERIFY = boolToString cfg.web.metrics.influxDb.insecureSkipVerify;

      EMIT_TO_LOGS = boolToString cfg.web.metrics.lager.emitToLogs;

      NEWRELIC_ACCOUNT_ID = cfg.web.metrics.newRelic.accoutId;
      NEWRELIC_API_KEY = cfg.web.metrics.newRelic.apiKey;
      NEWRELIC_SERVICE_PREFIX = cfg.web.metrics.newRelic.servicePrefix;

      PROMETHEUS_BIND_IP = cfg.web.metrics.prometheus.bindIp;
      PROMETHEUS_BIND_PORT = cfg.web.metrics.prometheus.bindPort;

      RIEMANN_HOST = cfg.web.metrics.riemann.host;
      RIEMANN_PORT = cfg.web.metrics.riemann.port;
      RIEMANN_SERVICE_PREFIX = cfg.web.metrics.riemann.servicePrefix;
      RIEMANN_TAG = cfg.web.metrics.riemann.tag;

      X_FRAME_OPTIONS = cfg.web.webServer.xFrameOptions;
      CLUSTER_NAME = cfg.web.webServer.clusterName;

      GC_INTERVAL = cfg.web.garbageCollection.interval;
      GC_ONE_OFF_GRACE_PERIOD = cfg.web.garbageCollection.oneOffGracePeriod;
      GC_MISSING_GRACE_PERIOD = cfg.web.garbageCollection.missingGracePeriod;

      SYSLOG_HOSTNAME = cfg.web.syslogDrainerConf.hostname;
      SYSLOG_ADDRESS = cfg.web.syslogDrainerConf.address;
      SYSLOG_TRANSPORT = cfg.web.syslogDrainerConf.transport;
      SYSLOG_DRAIN_INTERVAL = cfg.web.syslogDrainerConf.drainInterval;
      SYSLOG_CA_CERT = cfg.web.syslogDrainerConf.caCert;

      COOKIE_SECURE = boolToString cfg.web.authentication.cookieSecure;
      AUTH_DURATION = cfg.web.authentication.authDuration;
      SESSION_SIGNING_KEY = cfg.web.authentication.sessionSignKey;
      ADD_LOCAL_USER = cfg.web.authentication.addLocalUser;

      MAIN_TEAM_LOCAL_USER = cfg.web.authentication.mainTeamLocalUser;
      MAIN_TEAM_CONFIG = cfg.web.authentication.mainTeamConfig;

      MAIN_TEAM_BITBUCKET_CLOUD_USER = cfg.web.authentication.bitbucketCloud.user;
      MAIN_TEAM_BITBUCKET_CLOUD_TEAM = cfg.web.authentication.bitbucketCloud.team;
      BITBUCKET_CLOUD_CLIENT_ID = cfg.web.authentication.bitbucketCloud.clientId;
      BITBUCKET_CLOUD_CLIENT_SECRET = cfg.web.authentication.bitbucketCloud.clientSecret;

      MAIN_TEAM_CF_USER = cfg.web.authentication.cloudFoundry.user;
      MAIN_TEAM_CF_ORG = cfg.web.authentication.cloudFoundry.org;
      MAIN_TEAM_CF_SPACE = cfg.web.authentication.cloudFoundry.space;
      MAIN_TEAM_CF_SPACE_GUID = cfg.web.authentication.cloudFoundry.spaceGuid;
      CF_CLIENT_ID = cfg.web.authentication.cloudFoundry.clientId;
      CF_CLIENT_SECRET = cfg.web.authentication.cloudFoundry.clientSecret;
      CF_API_URL = cfg.web.authentication.cloudFoundry.apiUrl;
      CF_CA_CERT = cfg.web.authentication.cloudFoundry.caCert;
      CF_SKIP_SSL_VALIDATION = boolToString cfg.web.authentication.cloudFoundry.skipSslValidation;

      MAIN_TEAM_GITHUB_USER = cfg.web.authentication.github.user;
      MAIN_TEAM_GITHUB_ORG = cfg.web.authentication.github.org;
      MAIN_TEAM_GITHUB_TEAM = cfg.web.authentication.github.team;
      GITHUB_CLIENT_ID = cfg.web.authentication.github.clientId;
      GITHUB_CLIENT_SECRET = cfg.web.authentication.github.secret;
      GITHUB_HOST = cfg.web.authentication.github.host;
      GITHUB_CA_CERT = cfg.web.authentication.github.caCert;

      MAIN_TEAM_GITLAB_USER = cfg.web.authentication.gitlab.user;
      MAIN_TEAM_GITLAB_GROUP = cfg.web.authentication.gitlab.group;
      GITLAB_CLIENT_ID = cfg.web.authentication.gitlab.clientId;
      GITLAB_CLIENT_SECRET = cfg.web.authentication.gitlab.clientSecret;
      GITLAB_HOST = cfg.web.authentication.gitlab.host;

      MAIN_TEAM_LDAP_USER = cfg.web.authentication.ldap.user;
      MAIN_TEAM_LDAP_GROUP = cfg.web.authentication.ldap.group;
      LDAP_DISPLAY_NAME = cfg.web.authentication.ldap.displayName;
      LDAP_HOST = cfg.web.authentication.ldap.host;
      LDAP_BIND_DN = cfg.web.authentication.ldap.bindDn;
      LDAP_BIND_PW = cfg.web.authentication.ldap.bindPw;
      LDAP_INSECURE_NO_SSL = cfg.web.authentication.ldap.insecureNoSsl;
      LDAP_INSECURE_SKIP_VERIFY = cfg.web.authentication.ldap.insecureSkipVerify;
      LDAP_START_TLS = cfg.web.authentication.ldap.startTls;
      LDAP_CA_CERT = cfg.web.authentication.ldap.caCert;
      LDAP_USER_SEARCH_BASE_DN = cfg.web.authentication.ldap.userSearchBaseDn;
      LDAP_USER_SEARCH_FILTER = cfg.web.authentication.ldap.userSearchFilter;
      LDAP_USER_SEARCH_USERNAME = cfg.web.authentication.ldap.userSearchUsername;
      LDAP_USER_SEARCH_SCOPE = cfg.web.authentication.ldap.userSearchScope;
      LDAP_USER_SEARCH_ID_ATTR = cfg.web.authentication.ldap.userSearchIdAttr;
      LDAP_USER_SEARCH_EMAIL_ATTR = cfg.web.authentication.ldap.userSearchEmailAttr;
      LDAP_USER_SEARCH_NAME_ATTR = cfg.web.authentication.ldap.userSearchNameAttr;
      LDAP_GROUP_SEARCH_BASE_DN = cfg.web.authentication.ldap.groupSearchBaseDn;
      LDAP_GROUP_SEARCH_FILTER = cfg.web.authentication.ldap.groupSearchFilter;
      LDAP_GROUP_SEARCH_SCOPE = cfg.web.authentication.ldap.groupSearchScope;
      LDAP_GROUP_SEARCH_USER_ATTR = cfg.web.authentication.ldap.groupSearchUserAttr;
      LDAP_GROUP_SEARCH_GROUP_ATTR = cfg.web.authentication.ldap.groupSearchGroupAttr;
      LDAP_GROUP_SEARCH_NAME_ATTR = cfg.web.authentication.ldap.groupSearchNameAttr;

      MAIN_TEAM_OAUTH_USER = cfg.web.authentication.oauth2.user;
      MAIN_TEAM_OAUTH_GROUP = cfg.web.authentication.oauth2.group;
      OAUTH_DISPLAY_NAME = cfg.web.authentication.oauth2.displayName;
      OAUTH_CLIENT_ID = cfg.web.authentication.oauth2.clientId;
      OAUTH_CLIENT_SECRET = cfg.web.authentication.oauth2.clientSecret;
      OAUTH_AUTH_URL = cfg.web.authentication.oauth2.authUrl;
      OAUTH_TOKEN_URL = cfg.web.authentication.oauth2.tokenUrl;
      OAUTH_USERINFO_URL = cfg.web.authentication.oauth2.userinfoUrl;
      OAUTH_SCOPE = cfg.web.authentication.oauth2.scope;
      OAUTH_GROUPS_KEY = cfg.web.authentication.oauth2.groupsKey;
      OAUTH_USER_ID_KEY = cfg.web.authentication.oauth2.userIdKey;
      OAUTH_USER_NAME_KEY = cfg.web.authentication.oauth2.usernameKey;
      OAUTH_CA_CERT = cfg.web.authentication.oauth2.caCert;
      OAUTH_SKIP_SSL_VALIDATION = boolToString cfg.web.authentication.oauth2.skipSslValidation;
      
      MAIN_TEAM_OIDC_USER = cfg.web.authentication.oidc.user;
      MAIN_TEAM_OIDC_GROUP = cfg.web.authentication.oidc.group;
      OIDC_DISPLAY_NAME = cfg.web.authentication.oidc.displayName;
      OIDC_ISSUER = cfg.web.authentication.oidc.issuer;
      OIDC_CLIENT_ID = cfg.web.authentication.oidc.clientId;
      OIDC_CLIENT_SECRET = cfg.web.authentication.oidc.clientSecret;
      OIDC_SCOPE = cfg.web.authentication.oidc.scope;
      OIDC_GROUPS_KEY = cfg.web.authentication.oidc.groupsKey;
      OIDC_USER_NAME_KEY = cfg.web.authentication.oidc.usernameKey;
      OIDC_HOSTED_DOMAINS = cfg.web.authentication.oidc.hostedDomains;
      OIDC_CA_CERT = cfg.web.authentication.oidc.caCert;
      OIDC_SKIP_SSL_VALIDATION = cfg.web.authentication.oidc.skipSslValidation;

      TSA_LOG_LEVEL = cfg.web.tsa.logLevel;
      TSA_BIND_IP = cfg.web.tsa.bindIp;
      TSA_PEER_ADDRESS = cfg.web.tsa.peerAddress;
      TSA_BIND_PORT = cfg.web.tsa.bindPort;
      TSA_DEBUG_BIND_IP = cfg.web.tsa.debugBindIp;
      TSA_DEBUG_BIND_PORT = cfg.web.tsa.debugBindPort;
      TSA_HOST_KEY = cfg.web.tsa.hostKey;
      TSA_AUTHORIZED_KEYS = cfg.web.tsa.authorizedKeys;
      TSA_TEAM_AUTHORIZED_KEYS = cfg.web.tsa.teamAuthorizedKeys;
      TSA_ATC_URL = cfg.web.tsa.atcUrl;
      TSA_SESSION_SIGNING_KEY = cfg.web.tsa.sessionSigningKey;
      TSA_HEARTBEAT_INTERVAL = cfg.web.tsa.heartBeatInterval;
    };

    worker = {
      NAME = cfg.worker.name;
      TAG = cfg.worker.tag;
      TEAM = cfg.worker.team;
      EPHEMERAL = boolToString cfg.worker.ephemeral;
      CERTS_DIR = cfg.worker.certsDir;
      WORK_DIR = cfg.worker.workDir;
      BIND_IP = cfg.worker.bindIp;
      BIND_PORT = cfg.worker.bindPort;
      DEBUG_BIND_IP = cfg.worker.debugBindIp;
      DEBUG_BIND_PORT = cfg.worker.debugBindPort;
      HEALTHCHECK_BIND_IP = cfg.worker.healthcheckBindIp;
      HEALTHCHECK_BIND_PORT = cfg.worker.healthcheckBindPort;
      HEALTHCHECK_TIMEOUT = cfg.worker.healthchreckTimeout;
      SWEEP_INTERVAL = cfg.worker.sweepInterval;
      VOLUME_SWEEPER_MAX_IN_FLIGHT = cfg.worker.volumeSweeperMaxInFlight;
      CONTAINER_SWEEPER_MAX_IN_FLIGHT = cfg.worker.containerSweeperMaxInFlight;
      REBALANCE_INTERVAL = cfg.worker.rebalanceInterval;
      CONNECTION_DRAIN_TIMEOUT = cfg.worker.connectionDrainTimeout;
      EXTERNAL_GARDEN_URL = cfg.worker.externalGardenUrl;
      RESOURCE_TYPES = cfg.worker.resourceTypes;
      LOG_LEVEL = cfg.worker.logLevel;

      TSA_HOST = cfg.worker.tsa.host;
      TSA_PUBLIC_KEY = cfg.worker.tsa.publicKey;
      TSA_WORKER_PRIVATE_KEY = cfg.worker.tsa.workerPrivateKey;

      GARDEN_USE_HOUDINI = cfg.worker.useHoudini;
      GARDEN_BIN = cfg.worker.gardenBin;
      GARDEN_CONFIG = cfg.worker.gardenConfig;
      GARDEN_DNS_PROXY_ENABLE = boolToString cfg.worker.gardenDnsProxyEnable;

      BAGGAGECLAIM_LOG_LEVEL = cfg.worker.baggageclaim.logLevel;
      BAGGAGECLAIM_BIND_IP = cfg.worker.baggageclaim.bindIp;
      BAGGAGECLAIM_BIND_PORT = cfg.worker.baggageclaim.bindPort;
      BAGGAGECLAIM_DEBUG_BIND_IP = cfg.worker.baggageclaim.debugBindIp;
      BAGGAGECLAIM_DEBUG_BIND_PORT = cfg.worker.baggageclaim.debugBindPort;
      BAGGAGECLAIM_VOLUMES = cfg.worker.baggageclaim.volumes;
      BAGGAGECLAIM_DRIVER = cfg.worker.baggageclaim.driver;
      BAGGAGECLAIM_BTRFS_BIN = cfg.worker.baggageclaim.btrfsBin;
      BAGGAGECLAIM_MKFS_BIN = cfg.worker.baggageclaim.mkfsBin;
      BAGGAGECLAIM_OVERLAYS_DIR = cfg.worker.baggageclaim.overlaysDir;
      BAGGAGECLAIM_DISABLE_USER_NAMESPACES = boolToString cfg.worker.baggageclaim.disableUserNamespaces;
    };
  };

  webAllowedPorts = with cfg.web; [ 
    bindPort
    tlsBindPort
    tsa.bindPort
  ];

  workerAllowedPorts = with cfg.worker; [
    bindPort
    healthcheckBindPort
    baggageclaim.bindPort
  ];


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
        type = types.enum [
          "web"
          "worker"
          "quickstart"
          "land-worker"
          "retire-worker"
        ];
        default = "web";
        description = ''
          Sets Concourse working mode.
        '';
      };

      package = mkOption {
        type = types.package;
        default = pkgs.concourse;
        description = "Package to use.";
      };

      openFirewall = mkOption {
        type = bool;
        default = true;
        description = ''
          Open ports in the firewall for the Concourse web/worker.
        '';
      };
      
      # part of server interface
        
      web = with types; {
        generateKeys = mkOption {
          type = bool;
          default = false;
          description = "Generate SSH/RSA keys";
        };

        keysDir = mkOption {
          type = str;
          default = "/var/lib/concourse/web/keys/";
          description = "Directory in which keys will be stored.";
        };

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
          type = int;
          default = 8080;
          description = "Port on which to listen for HTTP traffic.";
        };

        tlsBindPort = mkOption {
          type = int;
          description = "Port on which to listen for HTTPS traffic.";
        };

        tlsCert = mkOption {
          type = path;
          default = "";
          description = "File containing an SSL certificate.";
        };

        tlsKey = mkOption {
          type = path;
          default = "";
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
          default = "";
          description = ''
            A 16 or 32 length key used to encrypt sensitive information
            before storing it in the database
          '';
        };
         
        oldEncryptionKey = mkOption {
          type = str;
          default = "";
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
          type = int;
          default = 8079;
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
            description = "IP address on which to listen for SSH.";
          };

          peerAddress = mkOption {
            type = str;
            default = "127.0.0.1";
            description = ''
              Network address of this web node, reachable by other web nodes.
              Used for forwarded worker addresses.           
            '';
          };
 
          bindPort = mkOption {
            type = int;
            default = 2222;
            description = "Port on which to listen for SSH.";
          };

          debugBindIp = mkOption {
            type = str;
            default = "127.0.0.1";
            description = ''
              IP address on which to listen for the pprof debugger endpoints.
            '';
          };

          debugBindPort = mkOption {
            type = int;
            default = 2221;
            description = ''
              Port on which to listen for the pprof debugger endpoints.
            '';
          };

          hostKey = mkOption {
            type = str;
            default = cfg.web.keysDir + "tsa_host_key";
            description = "Path to private key to use for the SSH server.";
          };

          authorizedKeys = mkOption {
            type = str;
            default = cfg.web.keysDir + "authorized_worker_keys";
            description = ''
              Path to file containing keys to authorize, 
              in SSH authorized_keys format.
              !!! All working keys must be added to this file !!!
            '';
          };

          teamAuthorizedKeys = mkOption {
            type = path;
            description = ''
              Path to file containing keys to authorize,
              in SSH authorized_keys format (one public key per line).
            '';
          };
 
          atcUrl = mkOption {
            type = str;
            description = ''
              ATC API endpoints to which workers will be registered.
            '';
          }; 

          sessionSigningKey = mkOption {
            type = path;
            default = "";
            description = ''
              Path to private key to use when signing tokens
              in reqests to the ATC during registration.
            '';
          };

          heartBeatInterval = mkOption {
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
            type = int;
            default = 5432;
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
              type = int;
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
            default = cfg.web.keysDir + "session_signing_key";
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

      # part of worker interface

      worker = with types; {
        generateKeys = mkOption {
          type = bool;
          default = false;
          description = "Generate SSH keys.";
        };

        keysDir = mkOption {
          type = str;
          default = "/var/lib/concourse/worker/keys/";
          description = "Directory in which keys will be stored.";
        };

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
          description = ''
            A tag to set during registration.
            Can be specified multiple times.
          '';
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
          type = int;
          default = 7777;
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
          type = int;
          default = 7776;
          description = "Port on which to listen for the pprof debugger endpoints.";
        };

        healthcheckBindIp = mkOption {
          type = str;
          default = "0.0.0.0";
          description = "IP address on which to listen for health checking requests.";
        };

        healthcheckBindPort = mkOption {
          type = int;
          default = 8888;
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
          host = mkOption {
            type = str;
            default = "127.0.0.1:2222";
            description = ''
              TSA host to forward the worker through.
              Can be specified multiple times.
            '';
          };

          publicKey = mkOption {
            type = str;
            default = cfg.worker.keysDir + "tsa_host_key.pub";
            description = ''
              File containing a public key to expect from the TSA.
            '';
          };

          workerPrivateKey = mkOption {
            type = str;
            default = cfg.worker.keysDir + "worker_key";
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
            type = str;
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
            type = int;
            default = 7788;
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
            type = int;
            default = 7787;
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

  config = mkIf cfg.enable {
    networking.firewall = mkIf cfg.openFirewall {
      allowedTCPPorts = flatten (
        (optional (cfg.mode == "web") webAllowedPorts)
        (optional (cfg.mode == "worker") workerAllowedPorts)
        (optional (cfg.mode == "quickstart") (webAllowedPorts ++ workerAllowedPorts))
      );
    };

    environment.systemPackages = [ cfg.package ];

    systemd.services.concourse = {
      description = "Concourse service daemon";
      wantedBy = ["multi-user.target"];
      
      requires = [(
        if cfg.mode == "web" || cfg.mode == "quickstart"
        then "postgresql.service" else ""
      )];

      after = [
        "networking.target"
      ] ++ requires;

      environment = {

      } // (if cfg.mode == "web"
            then
              mapAttrs' (n: v: nameValuePair "CONCOURSE_${n}" (toString v)) envOptions.web
            else if (cfg.mode == "worker" || cfg.mode == "land-worker" || cfg.mode == "retire-worker")
            then
              mapAttrs' (n: v: nameValuePair "CONCOURSE_${n}" (toString v)) envOptions.worker
            else 
              (mapAttrs' (n: v: nameValuePair "CONCOURSE_WORKER_${n}" (toString v)) (envOptions.worker)) // envOptions.web
           );

      script = ''
        ${optionalString cfg.web.generateKeys ''
          exec ${cfg.package}/bin/concourse generate-key -t rsa -f ${cfg.web.authentication.sessionSignKey}
          exec ${cfg.package}/bin/concourse generate-key -t ssh -f ${cfg.web.tsa.hostKey}
          touch ${cfg.web.tsa.authorizedKeys}
        ''}
        ${optionalString cfg.worker.generateKeys ''
          exec ${cfg.package}/bin/concourse generate-key -t ssh -f ${cfg.worker.tsa.workerPrivateKey}
        ''}
        exec ${cfg.package}/bin/concourse ${cfg.mode}
      '';
    };
  };
}
