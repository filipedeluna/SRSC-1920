package shared.parameters;

public enum ServerParameter {
  // Add parameters here

  // AEA
  PUB_KEY_ALG("pub_key_alg"),
  CERT_SIG_ALG("cert_sign_alg"),

  // DH
  DH_ALG("dh_alg"),
  DH_HASH_ALG("dh_hash_alg"),
  DH_KEYSIZE("dh_ks"),
  DH_P("dh_p"),
  DH_G("dh_g"),

  // Server signature of all parameters
  PARAM_SIG("param_sig");

  /////////////////////////////////////////////////

  private final String val;

  ServerParameter(String val) {
    this.val = val;
  }

  public String dbName() {
    return val;
  }
}

