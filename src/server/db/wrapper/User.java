package server.db.wrapper;

import java.io.Serializable;

public class User implements Serializable {
  public String id;
  public String uuid;

  public User() {}

  // Security Params
  public String dhValue;
  public String secDataSignature;
  public String pubKey;

  public User(String id, String uuid, String pubKey, String dhValue, String secDataSignature) {
    this.id = id;
    this.uuid = uuid;
    this.pubKey = pubKey;
    this.dhValue = dhValue;
    this.secDataSignature = secDataSignature;
  }

  public User(String uuid, String pubKey, String dhValue, String secDataSignature) {
    this.uuid = uuid;
    this.pubKey = pubKey;
    this.dhValue = dhValue;
    this.secDataSignature = secDataSignature;
  }
}
