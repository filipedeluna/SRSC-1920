package shared.utils;

import java.io.*;
import java.security.*;
import java.util.Base64;
import java.util.Random;

public abstract class CryptUtil {
  public static final String PROVIDER = "BC";

  private static final SecureRandom RANDOM = new SecureRandom();

  public static KeyStore loadKeystore(String file, String type, char[] pass) throws IOException, GeneralSecurityException {
    FileInputStream stream = new FileInputStream(file);

    KeyStore ks = KeyStore.getInstance(type, PROVIDER);
    ks.load(stream, pass);

    return ks;
  }

  public static byte[] joinByteArrays(byte[]... arrays) throws IOException {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

    for (byte[] array : arrays) {
      outputStream.write(array);
    }

    return outputStream.toByteArray();
  }

  public static String randomString(int size) {
    byte[] randomBytes = randomBytes(size);

    return Base64.getEncoder().encodeToString(randomBytes);
  }

  public static byte[] randomBytes(int size) {
    byte[] randomBytes = new byte[size];

    RANDOM.nextBytes(randomBytes);

    return randomBytes;
  }

  public static int randomInt() {
    return RANDOM.nextInt();
  }

  public static long randomLong() {
    return RANDOM.nextLong();
  }

  public static float randomFloat() {
    return RANDOM.nextFloat();
  }
}