package client;

import server.db.ServerParameterMap;
import server.db.ServerParameterType;

public class ClientDHHelper {
  private String dh_alg;
  private String dh_p;
  private String dh_g;
  private String dh_keysize;
  private String dh_hash;

  ClientDHHelper(ServerParameterMap spm){
    dh_alg = spm.get(ServerParameterType.DH_ALG).B;
    dh_p = spm.get(ServerParameterType.DH_P).B; // Big Int
    dh_g = spm.get(ServerParameterType.DH_G).B; // Big Int
    dh_keysize = spm.get(ServerParameterType.DH_KEYSIZE).B; // int
    dh_hash = spm.get(ServerParameterType.DH_HASH_ALG).B;

  }

  public String getDh_alg() {
    return dh_alg;
  }

  public String getDh_p() {
    return dh_p;
  }

  public String getDh_g() {
    return dh_g;
  }

  public String getDh_keysize() {
    return dh_keysize;
  }

  public String getDh_hash() {
    return dh_hash;
  }
}
