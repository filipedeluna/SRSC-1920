package shared.utils.crypto;

import shared.utils.CryptUtil;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public final class MacHelper {
  private Mac mac;
  private KeyGenerator keyGen;

  public MacHelper(String algorithm, String provider) throws GeneralSecurityException {
    mac = Mac.getInstance(algorithm, provider);
    keyGen = KeyGenerator.getInstance(algorithm, provider);
  }

  public boolean verifyMacHash(byte[] data, byte[] hash, Key key) throws InvalidKeyException {
    byte[] reHashedBytes = macHash(data, key);

    return MessageDigest.isEqual(reHashedBytes, hash);
  }

  public byte[] macHash(byte[] data, Key key) throws InvalidKeyException {
    mac.init(key);

    return mac.doFinal(data);
  }

  public int getMacSize() {
    return mac.getMacLength();
  }

  public SecretKey getKeyFromBytes(byte[] keyBytes) {
    return new SecretKeySpec(keyBytes, 0, mac.getMacLength(), mac.getAlgorithm());
  }

  public SecretKey generateKey() {
    keyGen.init(mac.getMacLength(), new SecureRandom());

    return keyGen.generateKey();
  }
}
