package client.props;

import shared.utils.properties.CustomPropertyType;
import shared.utils.properties.ICustomProperty;

public enum ClientProperty implements ICustomProperty {
  // Add properties here

  // System
  DEBUG("debug", CustomPropertyType.BOOL),
  OUTPUT_FOLDER("output_folder", CustomPropertyType.STRING),

  // Network
  PKI_ADDRESS("pki_address", CustomPropertyType.BOOL),
  PKI_PORT("pki_port", CustomPropertyType.INT),
  SERVER_ADDRESS("server_address", CustomPropertyType.BOOL),
  SERVER_PORT("server_port", CustomPropertyType.INT),
  TLS_PROTOCOLS("protocols", CustomPropertyType.STRING_ARRAY),
  TLS_CIPHERSUITES("ciphersuites", CustomPropertyType.STRING_ARRAY),

  // Crypt
  KEYSTORE_LOC("keystore_location", CustomPropertyType.STRING),
  KEYSTORE_TYPE("keystore_type", CustomPropertyType.STRING),
  KEYSTORE_PASS("keystore_pass", CustomPropertyType.STRING),
  CLIENT_PUB_KEY("client_pub_key", CustomPropertyType.STRING),
  CLIENT_CERT("client_cert", CustomPropertyType.STRING);

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
