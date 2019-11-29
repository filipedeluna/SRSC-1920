package shared.utils.crypto;

import shared.errors.crypto.InvalidPublicKeyException;

import javax.crypto.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.spec.X509EncodedKeySpec;

public class PubKeyHelper {
  private static final String PROVIDER = "BC";

  private static final SecureRandom secureRandom = new SecureRandom();

  private KeyPairGenerator keyPairGenerator;
  private KeyFactory keyFactory;
  private Signature signature;
  private int keySize;
  private Cipher cipher;

  public PubKeyHelper(String algorithm, int keySize) throws GeneralSecurityException {
    keyFactory = KeyFactory.getInstance(algorithm, PROVIDER);
    signature = Signature.getInstance(algorithm, PROVIDER);
    keyPairGenerator = KeyPairGenerator.getInstance(algorithm, PROVIDER);

    cipher = Cipher.getInstance(algorithm, PROVIDER);

    this.keySize = keySize;
  }

  public PublicKey RSAKeyFromBytes(byte[] keyBytes) throws GeneralSecurityException {
    return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
  }

  public byte[] dsaSign(PrivateKey key, byte[] data) throws GeneralSecurityException {
    signature.initSign(key, secureRandom);

    signature.update(data);

    return signature.sign();
  }

  public boolean dsaVerify(PublicKey key, byte[] data, byte[] dataSignature) throws GeneralSecurityException {
    signature.initVerify(key);

    signature.update(data);

    return signature.verify(dataSignature);
  }

  public byte[] encrypt(byte[] data, Key key) throws GeneralSecurityException {
    cipher.init(Cipher.ENCRYPT_MODE, key);

    return cipher.doFinal(data);
  }

  public byte[] decrypt(byte[] data, Key key) throws GeneralSecurityException {
    cipher.init(Cipher.DECRYPT_MODE, key);

    return cipher.doFinal(data);
  }

  public static KeyPair getKeyPair(KeyStore ks, char[] pass, String keyAlias) throws GeneralSecurityException {
    Key privateKey = ks.getKey(keyAlias, pass);

    Certificate cert = ks.getCertificate(keyAlias);

    PublicKey publicKey = cert.getPublicKey();

    if (!(privateKey instanceof PrivateKey))
      throw new InvalidPublicKeyException();

    return new KeyPair(publicKey, (PrivateKey) privateKey);
  }

  public KeyPair generateKeyPair() {
    keyPairGenerator.initialize(keySize);

    return keyPairGenerator.genKeyPair();
  }
}
