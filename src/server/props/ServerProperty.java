package server.props;

import shared.utils.properties.ICustomProperty;
import shared.utils.properties.CustomPropertyType;

public enum ServerProperty implements ICustomProperty {
  // Add properties here

  // System
  DEBUG("port", CustomPropertyType.BOOL),
  THREAD_POOL_SIZE("thread_pool_size", CustomPropertyType.INT),
  DATABASE_LOC("database_location", CustomPropertyType.STRING),
  DATABASE_FILES_LOC("database_files_location", CustomPropertyType.STRING),

  // Network
  PORT("port", CustomPropertyType.INT),
  TLS_MUTUAL_AUTH("tls_mutual_auth", CustomPropertyType.STRING),
  TLS_CIPHERSUITES("tls_ciphersuites", CustomPropertyType.STRING_ARRAY),
  TLS_PROTOCOLS("tls_protocols", CustomPropertyType.STRING_ARRAY),

  // Crypt
  KEYSTORE_LOC("keystore_location", CustomPropertyType.STRING),
  KEYSTORE_TYPE("keystore_type", CustomPropertyType.STRING),
  KEYSTORE_PASS("keystore_pass", CustomPropertyType.STRING),
  TRUSTSTORE_LOC("truststore_location", CustomPropertyType.STRING),
  TRUSTSTORE_TYPE("truststore_type", CustomPropertyType.STRING),
  TRUSTSTORE_PASS("truststore_pass", CustomPropertyType.STRING),

  HASH_ALG("hash_algorithm", CustomPropertyType.STRING),

  // PKI Server
  PKI_SERVER_ADDRESS("pki_server_address", CustomPropertyType.STRING),
  PKI_SERVER_PORT("pki_server_port", CustomPropertyType.INT);

  /////////////////////////////////////////////////

  private String val;
  private CustomPropertyType type;

  ServerProperty(String val, CustomPropertyType type) {
    this.val = val;
    this.type = type;
  }

  public String val() {
    return val;
  }

  public CustomPropertyType type() {
    return type;
  }
}
