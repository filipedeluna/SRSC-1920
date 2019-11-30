package pki.props;

import shared.utils.properties.PropertyType;

public enum PKIProperty {
  // Add properties here
  PORT("port", PropertyType.INT),

  KEYSTORE("keystore", PropertyType.STRING),
  KEYSTORE_PASS("keystore_pass", PropertyType.STRING),
  KEYSTORE_TYPE("keystore_type", PropertyType.STRING),

  TOKEN_VALUE("token_value", PropertyType.STRING),
  PKI_PUB_KEY("pki_public_key", PropertyType.STRING),
  PKI_CERT("pki_cert", PropertyType.STRING),

  HASH_ALGORITHM("hash_algorithm", PropertyType.STRING),

  DATABASE("database_location", PropertyType.STRING),

  CERTIFICATE_VALIDITY("certificate_validity", PropertyType.INT),

  THREAD_POOL_SIZE("thread_pool_size", PropertyType.INT),

  DEBUG("debug", PropertyType.BOOL),

  CIPHERSUITES("ciphersuites", PropertyType.STRING_ARRAY),
  PROTOCOLS("protocols", PropertyType.STRING_ARRAY);
  /////////////////////////////////////////////////
  private String val;
  private PropertyType type;

  PKIProperty(String val, PropertyType type) {
    this.val = val;
    this.type = type;
  }

  public String val() {
    return val;
  }

  PropertyType type() {
    return type;
  }
}
