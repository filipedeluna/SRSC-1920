package shared.utils.crypto.util;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;

public abstract class KeySizeFinder {
  private static final String PROVIDER = "BC";

  public static int findMaxSea(String algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException {
    Provider provider = Security.getProvider(PROVIDER);
    int maxKeySize = 0;

    for (Service service : provider.getServices()) {
      if (!service.getAlgorithm().equalsIgnoreCase(algorithm))
        continue;

      Cipher cipher = Cipher.getInstance(algorithm, provider);

      for (int keySize = Byte.SIZE; keySize <= 512; keySize += Byte.SIZE) {
        try {
          SecretKey key = new SecretKeySpec(new byte[keySize / Byte.SIZE], algorithm);
          cipher.init(Cipher.ENCRYPT_MODE, key);
          maxKeySize = keySize;
        } catch (Exception e) {
        }
      }

    }
    return maxKeySize;
  }

  public static int findMaxMac(String algorithm) throws NoSuchAlgorithmException {
    Provider provider = Security.getProvider(PROVIDER);
    int maxKeySize = 0;

    for (Service service : provider.getServices()) {
      if (!service.getAlgorithm().equalsIgnoreCase(algorithm))
        continue;

      Mac cipher = Mac.getInstance(algorithm, provider);

      for (int keySize = Byte.SIZE; keySize <= 9999; keySize += Byte.SIZE) {
        try {
          SecretKey key = new SecretKeySpec(new byte[keySize / Byte.SIZE], algorithm);
          cipher.init(key);
          maxKeySize = keySize;
        } catch (Exception e) {
        }
      }

    }
    return maxKeySize;
  }
}