package server.props;

import shared.utils.properties.ICustomProperty;
import shared.utils.properties.CustomPropertyType;

public enum ServerProperty implements ICustomProperty {
  // Add properties here

  // System
  DEBUG("port", CustomPropertyType.BOOL),
  THREAD_POOL_SIZE("thread_pool_size", CustomPropertyType.INT),
  DATABASE("database_location", CustomPropertyType.INT),

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

  HASH_ALG("hash_algorithm", CustomPropertyType.STRING);

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

