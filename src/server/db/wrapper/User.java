package server.db.wrapper;

public class User {
  public String id;
  public String uuid;

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
}
