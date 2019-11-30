package shared.utils;

import java.io.*;
import java.security.*;
import java.util.Base64;

public abstract class CryptoUtils {
  private static final SecureRandom secureRandom = new SecureRandom();

  public static KeyStore loadKeystore(String file, char[] pass) throws IOException, GeneralSecurityException {
    FileInputStream stream = new FileInputStream(file);

    KeyStore ks = KeyStore.getInstance("jceks");
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

  public static long generateRandomLong() {
    return secureRandom.nextLong();
  }

  public static long generateRandomInt() {
    return secureRandom.nextInt();
  }

  public static String generateRandomString(int size) {
    byte[] randomBytes = generateRandomBytes(size);

    return Base64.getEncoder().encodeToString(randomBytes);
  }

  public static byte[] generateRandomBytes(int size) {
    byte[] randomBytes = new byte[size];

    secureRandom.nextBytes(randomBytes);

    return randomBytes;
  }
}