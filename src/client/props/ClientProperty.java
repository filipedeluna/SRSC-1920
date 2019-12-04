package client.props;

import shared.utils.properties.CustomPropertyType;
import shared.utils.properties.ICustomProperty;

public enum ClientProperty implements ICustomProperty {
  // Add properties here
  PORT("port", CustomPropertyType.INT),

  // System
  DEBUG("debug", CustomPropertyType.BOOL),
  OUTPUT_FOLDER("output_folder", CustomPropertyType.STRING),

  // Network
  PKI_ADDRESS("pki_address", CustomPropertyType.BOOL),
  PKI_PORT("pki_port", CustomPropertyType.INT),
  SERVER_ADDRESS("server_address", CustomPropertyType.BOOL),
  SERVER_PORT("server_port", CustomPropertyType.INT),
  TLS_PROTOCOLS("tls_protocols", CustomPropertyType.STRING_ARRAY),
  TLS_CIPHERSUITES("tls_ciphersuites", CustomPropertyType.STRING_ARRAY),

  // Crypt
  KEYSTORE_LOC("keystore_location", CustomPropertyType.STRING),
  KEYSTORE_TYPE("keystore_type", CustomPropertyType.STRING),
  KEYSTORE_PASS("keystore_pass", CustomPropertyType.STRING),
  TRUSTSTORE_LOC("truststore_location", CustomPropertyType.STRING),
  TRUSTSTORE_TYPE("truststore_type", CustomPropertyType.STRING),
  TRUSTSTORE_PASS("truststore_pass", CustomPropertyType.STRING);

  /////////////////////////////////////////////////

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
