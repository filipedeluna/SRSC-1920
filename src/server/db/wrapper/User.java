package server.db.wrapper;

import java.io.Serializable;

public final class User implements Serializable {
  private String id;
  private String uuid;
  private String pubKey;

  // Security Params
  private String dhSeaPubKey;
  private String dhMacPubKey;
  private String seaSpec;
  private String macSpec;
  private String secDataSignature;

  public User() {
  }

  public User(String uuid, String pubKey, String dhSeaPubKey, String dhMacPubKey, String seaSpec, String macSpec, String secDataSignature) {
    this.uuid = uuid;
    this.pubKey = pubKey;
    this.dhSeaPubKey = dhSeaPubKey;
    this.dhMacPubKey = dhMacPubKey;
    this.seaSpec = seaSpec;
    this.macSpec = macSpec;
    this.secDataSignature = secDataSignature;
  }

  public User(String pubKey, String dhSeaPubKey, String dhMacPubKey, String seaSpec, String macSpec, String secDataSignature) {
    this.pubKey = pubKey;
    this.dhSeaPubKey = dhSeaPubKey;
    this.dhMacPubKey = dhMacPubKey;
    this.seaSpec = seaSpec;
    this.macSpec = macSpec;
    this.secDataSignature = secDataSignature;
  }

  public String getId() {
    return id;
  }

  public String getUuid() {
    return uuid;
  }

  public String getDhSeaPubKey() {
    return dhSeaPubKey;
  }

  public String getDhMacPubKey() {
    return dhMacPubKey;
  }

  public String getSeaSpec() {
    return seaSpec;
  }

  public String getMacSpec() {
    return macSpec;
  }

  public String getSecDataSignature() {
    return secDataSignature;
  }

  public String getPubKey() {
    return pubKey;
  }
}
