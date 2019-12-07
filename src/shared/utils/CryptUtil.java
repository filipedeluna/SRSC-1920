package shared.utils;

import javax.crypto.SecretKey;
import java.io.*;
import java.security.*;

public final class CryptUtil {


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