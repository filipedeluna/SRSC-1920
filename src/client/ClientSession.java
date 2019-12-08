package client;

import java.security.KeyPair;

public class ClientSession {
  private int id;
  private String seaSpec;
  private String macSpec;
  private KeyPair dhSeaKeyPair;
  private KeyPair dhMacKeyPair;

  public ClientSession(int id, String seaSpec, String macSpec, KeyPair dhSeaKeyPair, KeyPair dhMacKeyPair) {
    this.id = id;
    this.seaSpec = seaSpec;
    this.macSpec = macSpec;
    this.dhSeaKeyPair = dhSeaKeyPair;
    this.dhMacKeyPair = dhMacKeyPair;
  }

  public int getId() {
    return id;
  }

  public String getSeaSpec() {
    return seaSpec;
  }

  public String getMacSpec() {
    return macSpec;
  }

  public KeyPair getDhSeaKeyPair() {
    return dhSeaKeyPair;
  }

  public KeyPair getDhMacKeyPair() {
    return dhMacKeyPair;
  }
}
