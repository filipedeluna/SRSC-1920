package server.props;

import shared.utils.properties.ICustomProperty;
import shared.utils.properties.CustomPropertyType;

enum ServerProperty implements ICustomProperty {
  // Add properties here
  PORT("port", CustomPropertyType.INT),

  KEYSTORE("keystore", CustomPropertyType.STRING),
  KEYSTORE_PASS("keystore_pass", CustomPropertyType.STRING),
  KEYSTORE_TYPE("keystore_type", CustomPropertyType.STRING),

  TOKEN_VALUE("token_value", CustomPropertyType.STRING),
  PKI_PUB_KEY("pki_public_key", CustomPropertyType.STRING),
  PKI_CERT("pki_cert", CustomPropertyType.STRING),

  HASH_ALGORITHM("hash_algorithm", CustomPropertyType.STRING),

  DATABASE("database_location", CustomPropertyType.STRING),

  CERTIFICATE_VALIDITY("certificate_validity", CustomPropertyType.INT),

  THREAD_POOL_SIZE("thread_pool_size", CustomPropertyType.INT),

  DEBUG("debug", CustomPropertyType.BOOL),

  CIPHERSUITES("ciphersuites", CustomPropertyType.STRING_ARRAY),
  PROTOCOLS("protocols", CustomPropertyType.STRING_ARRAY);
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
