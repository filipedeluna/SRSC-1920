package client.cache;

public class UserCacheEntry extends CacheEntry {
  private byte[] pubKey;
  private byte[] dhSeaPubKey;
  private byte[] dhMacPubKey;
  private byte[] seaSpec;
  private byte[] macSpec;
  private byte[] secDataSignature;

  public UserCacheEntry(byte[] pubKey, byte[] dhSeaPubKey, byte[] dhMacPubKey, byte[] seaSpec, byte[] macSpec, byte[] secDataSignature) {
    this.pubKey = pubKey;
    this.dhSeaPubKey = dhSeaPubKey;
    this.dhMacPubKey = dhMacPubKey;
    this.seaSpec = seaSpec;
    this.macSpec = macSpec;
    this.secDataSignature = secDataSignature;

    // Get rough estimate of size
    size = pubKey.length + dhSeaPubKey.length + dhMacPubKey.length + seaSpec.length + macSpec.length + secDataSignature.length;
  }

  public byte[] getPubKey() {
    return pubKey;
  }

  public byte[] getDhSeaPubKey() {
    return dhSeaPubKey;
  }

  public byte[] getDhMacPubKey() {
    return dhMacPubKey;
  }

  public byte[] getSeaSpec() {
    return seaSpec;
  }

  public byte[] getMacSpec() {
    return macSpec;
  }

  public byte[] getSecDataSignature() {
    return secDataSignature;
  }
}
