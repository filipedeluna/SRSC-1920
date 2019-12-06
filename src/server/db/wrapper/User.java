package server.db.wrapper;

import java.io.Serializable;

public final class User implements Serializable {
  private String id;
  private String uuid;

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

  public String getId() {
    return id;
  }

  public String getUuid() {
    return uuid;
  }

  public String getDhValue() {
    return dhValue;
  }

  public String getSecDataSignature() {
    return secDataSignature;
  }

  public String getPubKey() {
    return pubKey;
  }
}
