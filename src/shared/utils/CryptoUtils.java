package shared.utils;

import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;

public abstract class CryptoUtils {
  private static final String PROVIDER = "BC";

  private static final int RANDOM_SIZE = 32;

  private static final SecureRandom secureRandom = new SecureRandom();

  public static KeyStore loadKeystore(String file, char[] pass) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
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