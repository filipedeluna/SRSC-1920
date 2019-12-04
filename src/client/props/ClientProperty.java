package client.props;

import shared.utils.properties.CustomPropertyType;
import shared.utils.properties.ICustomProperty;

public enum ClientProperty implements ICustomProperty {
  //TLS CONFIG
  TLS_CIPHERSUITES("tls_ciphersuites ", CustomPropertyType.STRING_ARRAY),
  TLS_PROTOCOLS("tls_protocols", CustomPropertyType.STRING_ARRAY),
  PORT("port", CustomPropertyType.INT),

  PUB_KEY_ALG("pub_key_alg", CustomPropertyType.STRING),
  PUB_KEY_SIZE("pub_key_size", CustomPropertyType.INT),
  CERT_SIGN_ALG("cert_sign_alg", CustomPropertyType.STRING),

  //CRYPT
  KEYSTORE_LOC("keystore_location", CustomPropertyType.STRING),
  TLS_MUTUAL_AUTH("tls_mutual_auth", CustomPropertyType.BOOL),
  KEYSTORE_TYPE("keystore_type", CustomPropertyType.STRING),
  KEYSTORE_PASS("keystore_pass", CustomPropertyType.STRING),
  TRUSTSTORE_LOC("truststore_location", CustomPropertyType.STRING),
  TRUSTSTORE_TYPE("truststore_type", CustomPropertyType.STRING),
  DEBUG("debug", CustomPropertyType.BOOL),
  TRUSTSTORE_PASS("truststore_pass", CustomPropertyType.STRING);




  private String val;
  private CustomPropertyType type;

  ClientProperty(String val, CustomPropertyType type) {
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
