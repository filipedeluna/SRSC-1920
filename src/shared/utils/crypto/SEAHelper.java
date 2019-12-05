package shared.utils.crypto;

import shared.utils.CryptUtil;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public final class SEAHelper {
  private String spec;
  private String mode;
  private Cipher cipher;
  private KeyGenerator keyGen;

  private RNDHelper random;

  public SEAHelper(String algorithm, String mode, String padding, RNDHelper random) throws GeneralSecurityException {
    this.mode = mode;
    this.random = random;

    spec = algorithm + "/" + mode + "/" + padding;
    cipher = Cipher.getInstance(spec, CryptUtil.PROVIDER);
    keyGen = KeyGenerator.getInstance(cipher.getAlgorithm(), CryptUtil.PROVIDER);
  }

  public byte[] decrypt(byte[] buff, Key key, byte[] iv) throws GeneralSecurityException {
    IvParameterSpec ivSpec = new IvParameterSpec(iv);

    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

    return cipher.doFinal(buff);
  }

  public byte[] decrypt(byte[] buff, Key key) throws GeneralSecurityException {
    cipher.init(Cipher.DECRYPT_MODE, key);

    return cipher.doFinal(buff);
  }

  public byte[] encrypt(byte[] buff, Key key, byte[] iv) throws GeneralSecurityException {
    IvParameterSpec ivSpec = new IvParameterSpec(iv);

    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

    return cipher.doFinal(buff);
  }

  public byte[] encrypt(byte[] buff, Key key) throws GeneralSecurityException {
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
    return random.getBytes(cipher.getBlockSize(), true);
  }

  public SecretKey generateKey() {
    keyGen.init(cipher.getBlockSize(), new SecureRandom());

    return keyGen.generateKey();
  }

  public String getSpec() {
    return spec;
  }
}
