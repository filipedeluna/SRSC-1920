package client;

import shared.utils.crypto.MacHelper;
import shared.utils.crypto.SEAHelper;

import java.security.GeneralSecurityException;
import java.security.KeyPair;

class ClientSession {
  private final int id;
  private final String uuid;
  private final String seaSpec;
  private final String macSpec;
  private final KeyPair dhSeaKeyPair;
  private final KeyPair dhMacKeyPair;

  MacHelper macHelper;
  SEAHelper seaHelper;

  ClientSession(String uuid, int id, String seaSpec, String macSpec, KeyPair dhSeaKeyPair, KeyPair dhMacKeyPair) throws GeneralSecurityException {
    this.uuid = uuid;
    this.id = id;
    this.seaSpec = seaSpec;
    this.macSpec = macSpec;
    this.dhSeaKeyPair = dhSeaKeyPair;
    this.dhMacKeyPair = dhMacKeyPair;

    // Start helpers
    String[] splitSpec = seaSpec.split("/");

    String algorithm = splitSpec[0];
    String mode = splitSpec[1];
    String padding = splitSpec[2];

    seaHelper = new SEAHelper(algorithm, mode, padding);
    macHelper = new MacHelper(macSpec);
  }

  public int getId() {
    return id;
  }

  public String getUUID() {
    return uuid;
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
