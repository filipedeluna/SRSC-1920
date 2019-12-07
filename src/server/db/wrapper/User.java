package server.db.wrapper;

import java.io.Serializable;

public final class User implements Serializable {
  private String id;
  private String uuid;
  public String pubKey;

  // Security Params
  public String dhValue;
  public String seaSpec;
  public String secDataSignature;

  public User() {
  }

  public User(String id, String uuid, String pubKey, String dhValue, String seaSpec, String secDataSignature) {
    this.id = id;
    this.uuid = uuid;
    this.pubKey = pubKey;
    this.dhValue = dhValue;
    this.seaSpec = seaSpec;
    this.secDataSignature = secDataSignature;
  }

  public User(String id, String pubKey, String dhValue, String seaSpec, String secDataSignature) {
    this.id = id;
    this.pubKey = pubKey;
    this.dhValue = dhValue;
    this.seaSpec = seaSpec;
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

  public String getSeaSpec() {
    return seaSpec;
  }

  public String getSecDataSignature() {
    return secDataSignature;
  }

  public String getPubKey() {
    return pubKey;
  }
}
