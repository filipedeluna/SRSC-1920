package shared.utils.crypto;

import shared.utils.CryptUtil;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class SEAHelper {
  private String spec;
  private String mode;
  private Cipher cipher;
  private KeyGenerator keyGen;

  public SEAHelper(String algorithm, String mode, String padding) throws GeneralSecurityException {
    this.mode = mode;

    spec = algorithm + "/" + mode + "/" + padding;
    cipher = Cipher.getInstance(spec, CryptUtil.PROVIDER);
    keyGen = KeyGenerator.getInstance(cipher.getAlgorithm(), CryptUtil.PROVIDER);
  }

  public byte[] decryptSymmetric(byte[] buff, Key key, byte[] iv) throws GeneralSecurityException {
    IvParameterSpec ivSpec = new IvParameterSpec(iv);

    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

    return cipher.doFinal(buff);
  }

  public byte[] decryptSymmetric(byte[] buff, Key key) throws GeneralSecurityException {
    cipher.init(Cipher.DECRYPT_MODE, key);

    return cipher.doFinal(buff);
  }

  public byte[] encryptSymmetric(byte[] buff, Key key, byte[] iv) throws GeneralSecurityException {
    IvParameterSpec ivSpec = new IvParameterSpec(iv);

    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

    return cipher.doFinal(buff);
  }

  public byte[] encryptSymmetric(byte[] buff, Key key) throws GeneralSecurityException {
    cipher.init(Cipher.ENCRYPT_MODE, key);

    return cipher.doFinal(buff);
  }

  public SecretKey getKeyFromBytes(byte[] keyBytes) {
    return new SecretKeySpec(keyBytes, 0, cipher.getBlockSize(), cipher.getAlgorithm());
  }

  public boolean cipherModeUsesIV() {
    return !mode.equals("ECB");
  }

  public byte[] generateIV() {
    byte[] iv = new byte[cipher.getBlockSize()];

    CryptUtil.RANDOM.nextBytes(iv);

    return iv;
  }

  public SecretKey generateKey() {
    keyGen.init(cipher.getBlockSize(), CryptUtil.RANDOM);

    return keyGen.generateKey();
  }

  public String spec() {
    return spec;
  }
}
