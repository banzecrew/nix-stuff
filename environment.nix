{ config, lib }:


with lib;


let
  cfg = config.services.concourse;
  
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

      TSA_LOG_LEVEL = cfg.web.tsaLogLevel;
      TSA_BIND_IP = cfg.web.tsaBindIp;
      TSA_PEER_ADDRESS = cfg.web.tsaPeerAddress;
      TSA_BIND_PORT = cfg.web.tsaBindPort;
      TSA_DEBUG_BIND_IP = cfg.web.tsaDebugBindIp;
      TSA_DEBUG_BIND_PORT = cfg.web.tsaDebugBindPort;
      TSA_HOST_KEY = cfg.web.tsaHostKey;
      TSA_AUTHORIZED_KEYS = cfg.web.tsaAuthorizedKeys;
      TSA_TEAM_AUTHORIZED_KEYS = cfg.web.tsaTeamAuthorizedKeys;
      TSA_ATC_URL = cfg.web.tsaAtcUrl;
      TSA_SESSION_SIGNING_KEY = cfg.web.tsaSessionSigningKey;
      TSA_HEARTBEAT_INTERVAL = cfg.web.tsaHeartBeatInterval;
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

      TSA_HOST = cfg.worker.tsaHost;
      TSA_PUBLIC_KEY = cfg.worker.tsaPublicKey;
      TSA_WORKER_PRIVATE_KEY = cfg.worker.tsaWorkerPrivateKey;

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

in envOptions
