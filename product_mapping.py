# ==========================================================
# ASTRA PRODUCT MAPPING
# ==========================================================
#
# Maps AI-normalized product names to the vendor/product
# identifiers commonly used for NVD CPE discovery.
#
# The AI normalization result should NOT be trusted blindly.
# This mapping provides deterministic identities for products
# that appear regularly in our tech-stack scans.
# ==========================================================


PRODUCT_MAPPINGS = {

    # ------------------------------------------------------
    # APACHE
    # ------------------------------------------------------

    "apache http server": {
        "vendor": "apache",
        "product": "http_server"
    },

    "http server": {
        "vendor": "apache",
        "product": "http_server"
    },

    "tomcat": {
        "vendor": "apache",
        "product": "tomcat"
    },

    "apache tomcat": {
        "vendor": "apache",
        "product": "tomcat"
    },

    "zookeeper": {
        "vendor": "apache",
        "product": "zookeeper"
    },

    "apache zookeeper": {
        "vendor": "apache",
        "product": "zookeeper"
    },

    "hadoop": {
        "vendor": "apache",
        "product": "hadoop"
    },

    "apache hadoop": {
        "vendor": "apache",
        "product": "hadoop"
    },

    "hbase": {
        "vendor": "apache",
        "product": "hbase"
    },

    "apache hbase": {
        "vendor": "apache",
        "product": "hbase"
    },

    # ------------------------------------------------------
    # DATABASES
    # ------------------------------------------------------

    "postgresql": {
        "vendor": "postgresql",
        "product": "postgresql"
    },

    "postgres": {
        "vendor": "postgresql",
        "product": "postgresql"
    },

    "mongodb": {
        "vendor": "mongodb",
        "product": "mongodb"
    },

    "mongodb atlas": {
        "vendor": "mongodb",
        "product": "mongodb"
    },

    "neo4j": {
        "vendor": "neo4j",
        "product": "neo4j"
    },

    "oracle database": {
        "vendor": "oracle",
        "product": "database_server"
    },

    "oracle": {
        "vendor": "oracle",
        "product": "database_server"
    },

    # ------------------------------------------------------
    # MESSAGING / QUEUES
    # ------------------------------------------------------

    "rabbitmq": {
        "vendor": "rabbitmq",
        "product": "rabbitmq"
    },

    "rabbit mq": {
        "vendor": "rabbitmq",
        "product": "rabbitmq"
    },

    "rabbitmq server": {
        "vendor": "rabbitmq",
        "product": "rabbitmq"
    },

    "spring amqp": {
        "vendor": "vmware",
        "product": "spring_amqp"
    },

    # ------------------------------------------------------
    # JAVA
    # ------------------------------------------------------

    "openjdk": {
        "vendor": "oracle",
        "product": "openjdk"
    },

    "java": {
        "vendor": "oracle",
        "product": "openjdk"
    },

    "java terrarium": {
        "vendor": "oracle",
        "product": "openjdk"
    },

    "eclipse temurin": {
        "vendor": "eclipse",
        "product": "temurin"
    },

    "temurin": {
        "vendor": "eclipse",
        "product": "temurin"
    },

    # ------------------------------------------------------
    # SPRING
    # ------------------------------------------------------

    "spring boot": {
        "vendor": "vmware",
        "product": "spring_boot"
    },

    "spring": {
        "vendor": "vmware",
        "product": "spring_framework"
    },

    # ------------------------------------------------------
    # PYTHON
    # ------------------------------------------------------

    "python": {
        "vendor": "python",
        "product": "python"
    },

    "python 3": {
        "vendor": "python",
        "product": "python"
    },

    # ------------------------------------------------------
    # FRONTEND
    # ------------------------------------------------------

    "angular": {
        "vendor": "google",
        "product": "angular"
    },

    "angularjs": {
        "vendor": "google",
        "product": "angular"
    },

    "bootstrap": {
        "vendor": "getbootstrap",
        "product": "bootstrap"
    },

    "highcharts": {
        "vendor": "highsoft",
        "product": "highcharts"
    },

    # ------------------------------------------------------
    # PROXY / LOAD BALANCER
    # ------------------------------------------------------

    "haproxy": {
        "vendor": "haproxy",
        "product": "haproxy"
    },

    "ha proxy": {
        "vendor": "haproxy",
        "product": "haproxy"
    },

    # ------------------------------------------------------
    # ELASTIC STACK
    # ------------------------------------------------------

    "elasticsearch": {
        "vendor": "elastic",
        "product": "elasticsearch"
    },

    "logstash": {
        "vendor": "elastic",
        "product": "logstash"
    },

    "metricbeat": {
        "vendor": "elastic",
        "product": "metricbeat"
    },

    "heartbeat": {
        "vendor": "elastic",
        "product": "heartbeat"
    },

    # ------------------------------------------------------
    # LOGGING / OBSERVABILITY
    # ------------------------------------------------------

    "fluentd": {
        "vendor": "fluentd",
        "product": "fluentd"
    },

    "grafana": {
        "vendor": "grafana",
        "product": "grafana"
    },

    "opentelemetry": {
        "vendor": "opentelemetry",
        "product": "opentelemetry"
    },

    # ------------------------------------------------------
    # NETWORK / SECURITY
    # ------------------------------------------------------

    "net-snmp": {
        "vendor": "net-snmp",
        "product": "net-snmp"
    },

    "snmp": {
        "vendor": "net-snmp",
        "product": "net-snmp"
    },

    # ------------------------------------------------------
    # DEVELOPMENT / BUILD
    # ------------------------------------------------------

    "gradle": {
        "vendor": "gradle",
        "product": "gradle"
    },

    "podman": {
        "vendor": "redhat",
        "product": "podman"
    },

    # ------------------------------------------------------
    # MOBILE / CROSS PLATFORM
    # ------------------------------------------------------

    "flutter": {
        "vendor": "google",
        "product": "flutter"
    },

    # ------------------------------------------------------
    # TESTING
    # ------------------------------------------------------

    "selenium": {
        "vendor": "selenium",
        "product": "selenium"
    },

    # ------------------------------------------------------
    # CONNECTION POOLING
    # ------------------------------------------------------

    "pgpool-ii": {
        "vendor": "pgpool",
        "product": "pgpool-ii"
    },

    "pgpool": {
        "vendor": "pgpool",
        "product": "pgpool-ii"
    },

    # ------------------------------------------------------
    # IDENTITY / SECURITY
    # ------------------------------------------------------

    "keycloak": {
        "vendor": "redhat",
        "product": "keycloak"
    },

    # ------------------------------------------------------
    # NEO4J / ELASTIC / OTHER
    # ------------------------------------------------------

    "neo4j database": {
        "vendor": "neo4j",
        "product": "neo4j"
    },
    "erlang/otp": {
            "vendor": "erlang",
            "product": "erlang/otp"
        }
}


def get_product_mapping(product):

    if not product:
        return None

    key = product.lower().strip()

    return PRODUCT_MAPPINGS.get(key)