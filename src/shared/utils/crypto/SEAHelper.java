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

  public SEAHelper(String seaSpec) throws NoSuchProviderException, NoSuchAlgorithmException, NoSuchPaddingException {
    this.random = new RNDHelper();

    String[] splitSpec = seaSpec.split("/");

    if (splitSpec.length != 3)
      throw new NoSuchAlgorithmException("Invalid sea spec.");

    String alg = splitSpec[0];
    mode = splitSpec[1];

    // Force removal of unnecessary padding for cipher types
    if (mode.equals("GCM") || mode.equals("CCM"))
      spec = alg + "/" + mode + "/NoPadding";
    else
      spec = seaSpec;

    cipher = Cipher.getInstance(spec, PROVIDER);
    keyGen = KeyGenerator.getInstance(alg, PROVIDER);
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

  public int getMaxKeySize() throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
    String alg = cipher.getAlgorithm().split("/")[0];
    return KeySizeFinder.findMaxSea(alg);
  }

  public int ivSize() {
    return cipher.getBlockSize();
  }
}
