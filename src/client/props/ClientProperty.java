package client.props;

import shared.utils.properties.CustomPropertyType;
import shared.utils.properties.ICustomProperty;

public enum ClientProperty implements ICustomProperty {
  // Add properties here

  // System
  OUTPUT_FOLDER("output_folder", CustomPropertyType.STRING),
  CACHE_SIZE("cache_size", CustomPropertyType.INT),

  // Network
  PKI_ADDRESS("pki_address", CustomPropertyType.STRING),
  PKI_PORT("pki_port", CustomPropertyType.INT),
  SERVER_ADDRESS("server_address", CustomPropertyType.STRING),
  SERVER_PORT("server_port", CustomPropertyType.INT),
  TLS_PROTOCOLS("tls_protocols", CustomPropertyType.STRING_ARRAY),
  TLS_CIPHERSUITES("tls_ciphersuites", CustomPropertyType.STRING_ARRAY),
  BUFFER_SIZE_MB("buffer_size_megabytes", CustomPropertyType.INT),

  // Crypt
  SEA_SPEC("sea_spec", CustomPropertyType.STRING),
  MAC_SPEC("mac_spec", CustomPropertyType.STRING),
  UUID_HASH("uuid_hash", CustomPropertyType.STRING),
  PUB_KEY_NAME("pub_key_name", CustomPropertyType.STRING),
  KEYSTORE_LOC("keystore_location", CustomPropertyType.STRING),
  KEYSTORE_TYPE("keystore_type", CustomPropertyType.STRING),
  KEYSTORE_PASS("keystore_pass", CustomPropertyType.STRING),
  TRUSTSTORE_LOC("truststore_location", CustomPropertyType.STRING),
  TRUSTSTORE_TYPE("truststore_type", CustomPropertyType.STRING),
  TRUSTSTORE_PASS("truststore_pass", CustomPropertyType.STRING),

  // PKI
  USE_PKI("use_pki", CustomPropertyType.BOOL),
  PKI_TOKEN("123asd", CustomPropertyType.STRING),
  PKI_CERT_ALG("pki_cert_sign_alg", CustomPropertyType.STRING),
  PKI_PUBKEY_SIZE("pki_pubkey_size", CustomPropertyType.INT),
  PKI_KEY_ALG("pki_pubkey_algorithm", CustomPropertyType.STRING);

  /////////////////////////////////////////////////

  private final String val;
  private final CustomPropertyType type;

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
