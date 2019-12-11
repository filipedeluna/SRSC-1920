package shared.utils.crypto.util;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider.Service;
import java.security.Security;

public abstract class KeySizeFinder {
  private static final String PROVIDER = "BC";

  public static int findMaxSea(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
    for (Service service : Security.getProvider(PROVIDER).getServices()) {
      if (!service.getAlgorithm().equalsIgnoreCase(algorithm))
        continue;

      Cipher cipher = Cipher.getInstance(algorithm, PROVIDER);
      int maxKeySize = 0;

      for (int keySize = 1; keySize <= 64; keySize++) {
        try {
          SecretKey key = new SecretKeySpec(new byte[keySize], algorithm);
          cipher.init(Cipher.ENCRYPT_MODE, key);

          maxKeySize = keySize;
        } catch (Exception ignored) { }
      }
      return maxKeySize;
    }
    throw new NoSuchAlgorithmException("Failed to find algorithm size.");
  }

  public static int findMaxMac(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
    for (Service service : Security.getProvider(PROVIDER).getServices()) {
      if (!service.getAlgorithm().equalsIgnoreCase(algorithm))
        continue;

      Mac cipher = Mac.getInstance(algorithm, PROVIDER);
      int maxKeySize = 0;

      for (int keySize = 1; keySize <= 64; keySize++) {
        try {
          SecretKey key = new SecretKeySpec(new byte[keySize], algorithm);
          cipher.init(key);

          maxKeySize = keySize;
        } catch (Exception ignored) { }
      }
      return maxKeySize;
    }
    throw new NoSuchAlgorithmException("Failed to find algorithm size.");
  }
}