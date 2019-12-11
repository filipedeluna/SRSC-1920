package shared.utils.crypto;

import shared.utils.crypto.util.KeySizeFinder;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;

public final class SEAHelper {
  private static final String PROVIDER = "BC";

  private final String spec;
  private final String mode;
  private Cipher cipher;
  private KeyGenerator keyGen;

  private final RNDHelper random;

  public SEAHelper(String algorithm, String mode, String padding) throws GeneralSecurityException {
    this.random = new RNDHelper();
    this.mode = mode;

    // Force removal of unnecessary padding for cipher types
    if (mode.equals("GCM") || mode.equals("CCM"))
      spec = algorithm + "/" + mode + "/NoPadding";
    else
      spec = algorithm + "/" + mode + "/" + padding;

    cipher = Cipher.getInstance(spec, PROVIDER);
    keyGen = KeyGenerator.getInstance(algorithm, PROVIDER);
  }

  public byte[] decrypt(byte[] buff, Key key, byte[] iv) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {
    IvParameterSpec ivSpec = new IvParameterSpec(iv);

    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

    return cipher.doFinal(buff);
  }

  public byte[] decrypt(byte[] buff, Key key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    cipher.init(Cipher.DECRYPT_MODE, key);

    return cipher.doFinal(buff);
  }

  public byte[] encrypt(byte[] buff, Key key, byte[] iv) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {
    IvParameterSpec ivSpec = new IvParameterSpec(iv);

    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

    return cipher.doFinal(buff);
  }

  public byte[] encrypt(byte[] buff, Key key) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
    cipher.init(Cipher.ENCRYPT_MODE, key);

    return cipher.doFinal(buff);
  }

  public SecretKey getKeyFromBytes(byte[] keyBytes) {
    return new SecretKeySpec(keyBytes, cipher.getAlgorithm());
  }

  public boolean cipherModeUsesIV() {
    return !mode.equals("ECB");
  }

  public byte[] generateIV() {
    return random.getBytes(cipher.getBlockSize(), false);
  }

  public SecretKey generateKey() {
    keyGen.init(cipher.getBlockSize(), new SecureRandom());

    return keyGen.generateKey();
  }

  public byte[] trimKeyToAlg(byte[] key) {
    return Arrays.copyOfRange(key, 0, cipher.getBlockSize());
  }

  public String getSpec() {
    return spec;
  }

  public int getMaxKeySize() throws NoSuchAlgorithmException, NoSuchPaddingException {
    String alg = cipher.getAlgorithm().split("/")[0];
    return KeySizeFinder.findMaxSea(alg);
  }

  public int ivSize() {
    return cipher.getBlockSize();
  }
}
