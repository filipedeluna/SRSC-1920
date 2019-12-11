package client.cache;

import java.security.PublicKey;

public class UserCacheEntry extends CacheEntry {
  private final PublicKey pubKey;
  private final byte[] dhSeaPubKey;
  private final byte[] dhMacPubKey;
  private final String seaSpec;
  private final String macSpec;

  public UserCacheEntry(PublicKey pubKey, byte[] dhSeaPubKey, byte[] dhMacPubKey, String seaSpec, String macSpec) {
    this.pubKey = pubKey;
    this.dhSeaPubKey = dhSeaPubKey;
    this.dhMacPubKey = dhMacPubKey;
    this.seaSpec = seaSpec;
    this.macSpec = macSpec;

    // Get rough estimate of size
    size = pubKey.getEncoded().length + dhSeaPubKey.length + dhMacPubKey.length + seaSpec.getBytes().length + macSpec.getBytes().length;
  }

  public PublicKey getPubKey() {
    return pubKey;
  }

  public byte[] getDhSeaPubKey() {
    return dhSeaPubKey;
  }

  public byte[] getDhMacPubKey() {
    return dhMacPubKey;
  }

  public String getSeaSpec() {
    return seaSpec;
  }

  public String getMacSpec() {
    return macSpec;
  }
}
