package pki.props;

import shared.utils.properties.ICustomProperty;
import shared.utils.properties.CustomPropertyType;

public enum PKIProperty implements ICustomProperty {
  // Add properties here

  // System
  DEBUG("debug", CustomPropertyType.BOOL),
  THREAD_POOL_SIZE("thread_pool_size", CustomPropertyType.INT),
  DATABASE_LOC("database_location", CustomPropertyType.STRING),

  // Network,
  PORT("port", CustomPropertyType.INT),
  TLS_CIPHERSUITES("ciphersuites", CustomPropertyType.STRING_ARRAY),
  TLS_PROTOCOLS("protocols", CustomPropertyType.STRING_ARRAY),


  // Crypt
  KEYSTORE_LOC("keystore", CustomPropertyType.STRING),
  KEYSTORE_TYPE("keystore_type", CustomPropertyType.STRING),
  KEYSTORE_PASS("keystore_pass", CustomPropertyType.STRING),

  PKI_PUB_KEY("pki_public_key", CustomPropertyType.STRING),
  PKI_CERT("pki_cert", CustomPropertyType.STRING),

  HASH_ALGORITHM("hash_algorithm", CustomPropertyType.STRING),

  // PKI Properties
  TOKEN_VALUE("token_value", CustomPropertyType.STRING),
  CERTIFICATE_VALIDITY("certificate_validity", CustomPropertyType.INT);





  /////////////////////////////////////////////////
  private String val;
  private CustomPropertyType type;

  PKIProperty(String val, CustomPropertyType type) {
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
