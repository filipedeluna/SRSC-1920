package shared.utils.crypto;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class MacHelper {
  private static final String PROVIDER = "BC";

  private static final SecureRandom secureRandom = new SecureRandom();

  private Mac mac;
  private KeyGenerator keyGen;

  public MacHelper(String algorithm) throws GeneralSecurityException {
    mac = Mac.getInstance(algorithm, PROVIDER);
    keyGen = KeyGenerator.getInstance(algorithm, PROVIDER);
  }

  public boolean verifyMacHash(byte[] data, byte[] hash, Key key) throws InvalidKeyException {
    byte[] reHashedBytes = macHash(data, key);

    return MessageDigest.isEqual(reHashedBytes, hash);
  }

  public byte[] macHash(byte[] data, Key key) throws InvalidKeyException {
    mac.init(key);

    return mac.doFinal(data);
  }

  public int macSize() {
    return mac.getMacLength();
  }

  public SecretKey keyFromBytes(byte[] keyBytes) {
    return new SecretKeySpec(keyBytes, 0, mac.getMacLength(), mac.getAlgorithm());
  }

  public SecretKey generateKey() {
    keyGen.init(mac.getMacLength(), secureRandom);

    return keyGen.generateKey();
  }
}
