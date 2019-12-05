package shared.utils;

import java.io.*;
import java.security.*;

public final class CryptUtil {
  public static final String PROVIDER = "BC";
  public static final String PROVIDER_TLS = "BCJSSE";

  private static final SecureRandom RANDOM = new SecureRandom();

  public static KeyStore loadKeystore(String file, String type, char[] pass) throws IOException, GeneralSecurityException {
    FileInputStream stream = new FileInputStream(file);

    KeyStore ks = KeyStore.getInstance(type);
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
}