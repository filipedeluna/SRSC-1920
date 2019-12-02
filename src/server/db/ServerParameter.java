package server.db;


public enum ServerParameter {
  // Add parameters here

  // DH
  DH_ALG("dh_alg"),
  DH_KS("dh_ks"),
  DH_P("dh_p"),
  DH_G("dh_g"),
  DH_PARAM_SIG("dh_param_sig");

  /////////////////////////////////////////////////

  private String val;

  ServerParameter(String val) {
    this.val = val;
  }

  public String val() {
    return val;
  }
}

