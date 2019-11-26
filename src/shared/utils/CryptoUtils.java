package shared.utils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public abstract class CryptoUtils {
  private static final String PROVIDER = "BC";
  private static final String PUBLIC_KEY_CIPHER = "RSA/None/PKCS1Padding";
  private static final String PUBLIC_KEY_ALGORITHM = "RSA";
  private static final String CERTIFICATE_FORMAT = "X.509";

  private static final String SIGNATURE_CIPHER = "SHA256withECDSA";
  private static final String SIGNATURE_ALG = "DSA";

  private static final String SESSION_CIPHER_ALG = "AES/GCM/NoPadding";
  private static final String SESSION_KEY_ALG = "AES";
  private static final String PWD_MAC_ALG = "HMacSHA256";
  private static final int PWD_MAC_KS = 32;
  private static final String PWD_HASH_ALG = "SHA256";

  private static final int TOKEN_SIZE = 32;

  private static final int SESSION_KEY_SIZE_BITS = 256;
  private static final int SESSION_KEY_SIZE_BYTES = SESSION_KEY_SIZE_BITS / 8;
  private static final int SESSION_MAC_KEY_SIZE = 256;

  private static final int DH_KEY_SIZE = 2048;

  private static final int PUBLIC_KEY_SIZE = 2048;

  private static final int RANDOM_SIZE = 32;

  private static final SecureRandom secureRandom = new SecureRandom();

  public static KeyStore loadKeystore(String file, char[] pass) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
    FileInputStream stream = new FileInputStream(file);

    KeyStore ks = KeyStore.getInstance("jceks");
    ks.load(stream, pass);

    return ks;
  }

  public static boolean cipherModeUsesIV(String mode) {
    return !mode.toUpperCase().equals("ECB");
  }

  public static byte[] getIV(Cipher cipher) {
    byte[] iv = new byte[getIVSize(cipher)];

    secureRandom.nextBytes(iv);

    return iv;
  }

  public static int getIVSize(Cipher cipher) {
    return cipher.getBlockSize();
  }

  public static byte[] decryptSymmetric(byte[] buff, Cipher cipher, Key key, byte[] iv) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    IvParameterSpec ivSpec = new IvParameterSpec(iv);

    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

    return cipher.doFinal(buff);
  }

  public static byte[] decryptSymmetric(byte[] buff, Cipher cipher, Key key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    cipher.init(Cipher.DECRYPT_MODE, key);

    return cipher.doFinal(buff);
  }

  public static byte[] encryptSymmetric(byte[] buff, Cipher cipher, Key key, byte[] iv) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
    IvParameterSpec ivSpec = new IvParameterSpec(iv);

    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

    return cipher.doFinal(buff);
  }

  public static byte[] encryptSymmetric(byte[] buff, Cipher cipher, Key key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    cipher.init(Cipher.ENCRYPT_MODE, key);

    return cipher.doFinal(buff);
  }

  public static byte[] hash(byte[] data, String algorithm) throws NoSuchProviderException, NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance(algorithm, PROVIDER);

    return md.digest(data);
  }

  public static byte[] pwdHash(byte[] data) throws NoSuchProviderException, NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance(PWD_HASH_ALG, PROVIDER);

    return md.digest(data);
  }

  public static boolean verifyHash(byte[] data, byte[] hash, String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
    byte[] reHashedBytes = hash(data, algorithm);

    return MessageDigest.isEqual(reHashedBytes, hash);
  }

  public static byte[] joinByteArrays(byte[]... arrays) throws IOException {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

    for (byte[] array : arrays) {
      outputStream.write(array);
    }

    return outputStream.toByteArray();
  }

  public static boolean verifyMacHash(byte[] data, byte[] hash, Mac mac, Key key) throws InvalidKeyException {
      byte[] reHashedBytes = macHash(data, mac, key);

      return MessageDigest.isEqual(reHashedBytes, hash);
  }

  public static byte[] macHash(byte[] data, Mac mac, Key key) throws InvalidKeyException {
    mac.init(key);

      return mac.doFinal(data);
  }

  public static int getHashSize(String algorithm) throws NoSuchAlgorithmException {
    return MessageDigest.getInstance(algorithm).getDigestLength();
  }

  public static int getMacSize(String algorithm) throws NoSuchAlgorithmException {
    return Mac.getInstance(algorithm).getMacLength();
  }

  public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance(PUBLIC_KEY_ALGORITHM, PROVIDER);

    kpg.initialize(PUBLIC_KEY_SIZE);

    return kpg.genKeyPair();
  }

  public static KeyPair getKeyPair(KeyStore ks, char[] pass, String keyAlias) throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
    Key privateKey = ks.getKey(keyAlias, pass);

    Certificate cert = ks.getCertificate(keyAlias);

    PublicKey publicKey = cert.getPublicKey();

    // if (!(privateKey instanceof PrivateKey))
     // throw new InvalidPrivateKeyException();

    return new KeyPair(publicKey, (PrivateKey) privateKey);
  }

  public static Certificate getCertificateFromFile(String file) throws CertificateException, NoSuchProviderException, FileNotFoundException {
    CertificateFactory cf = CertificateFactory.getInstance(CERTIFICATE_FORMAT, PROVIDER);

    return cf.generateCertificate(new FileInputStream(file));
  }

  public static byte[] encryptWithPublicKey(byte[] data, Cipher cipher, PublicKey key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    cipher.init(Cipher.ENCRYPT_MODE, key);

    return cipher.doFinal(data);
  }

  public static byte[] encryptWithPrivateKey(byte[] data, Cipher cipher, PrivateKey key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    cipher.init(Cipher.ENCRYPT_MODE, key);

    return cipher.doFinal(data);
  }

  public static byte[] decryptWithPublicKey(byte[] data, Cipher cipher, PublicKey key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    cipher.init(Cipher.DECRYPT_MODE, key);

    return cipher.doFinal(data);
  }

  public static byte[] decryptWithPrivateKey(byte[] data, Cipher cipher, PrivateKey key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    cipher.init(Cipher.DECRYPT_MODE, key);

    return cipher.doFinal(data);
  }

  public static SecretKey generateSessionKeyFromBytes(byte[] keyBytes) {
    return new SecretKeySpec(keyBytes, 0, SESSION_KEY_SIZE_BYTES, SESSION_KEY_ALG);
  }

  public static SecretKey generatePwdMacKey(byte[] keyBytes) {
    return new SecretKeySpec(keyBytes, 0, PWD_MAC_KS, PWD_MAC_ALG);
  }


  public static PublicKey generatePublicKeyFromBytes(byte[] keyBytes) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
    return KeyFactory.getInstance(PUBLIC_KEY_ALGORITHM, PROVIDER).generatePublic(new X509EncodedKeySpec(keyBytes));
  }

  public static SSLContext getSSLContext(KeyStore keyStore, char[] pass) throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, KeyManagementException {
    SSLContext ctx = SSLContext.getInstance("TLSv1.2");

    KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
    kmf.init(keyStore, pass);

    TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
    tmf.init(keyStore);

    ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), secureRandom);

    return ctx;
  }

  public static Cipher getSessionRSACipher() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
    return Cipher.getInstance(PUBLIC_KEY_CIPHER, PROVIDER);
  }

  public static Cipher getSessionAESCipher() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
    return Cipher.getInstance(SESSION_CIPHER_ALG, PROVIDER);
  }

  public static Mac getPasswordMac() throws NoSuchAlgorithmException {
    return Mac.getInstance(PWD_MAC_ALG);
  }

  public static SecretKey generateSessionKey() throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyGenerator kg = KeyGenerator.getInstance(SESSION_KEY_ALG, PROVIDER);

    kg.init(SESSION_KEY_SIZE_BITS, secureRandom);

    return kg.generateKey();
  }

  public static SecretKey generateChatroomKey(String keyAlg, int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyGenerator kg = KeyGenerator.getInstance(keyAlg, PROVIDER);

    kg.init(keySize, secureRandom);

    return kg.generateKey();
  }

  public static byte[] generateRandomString() {
    byte[] random = new byte[RANDOM_SIZE];

    secureRandom.nextBytes(random);

    return random;
  }

  public static KeyPair getDHKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException {
    KeyPairGenerator dhKp = KeyPairGenerator.getInstance("DH", PROVIDER);
    dhKp.initialize(DH_KEY_SIZE);

    return dhKp.generateKeyPair();
  }

  public static SecretKey generateDHSharedKey(PrivateKey aKey, PublicKey bKey) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, ShortBufferException {
    KeyAgreement keyAgreement = KeyAgreement.getInstance("DH", PROVIDER);

    keyAgreement.init(aKey);

    keyAgreement.doPhase(bKey, true); // true - last phase

    byte[] sharedSecret = new byte[SESSION_KEY_SIZE_BYTES];

    keyAgreement.generateSecret(sharedSecret, sharedSecret.length);

    return generateSessionKeyFromBytes(sharedSecret);
  }

  public static byte[] dsaSign(PrivateKey key, byte[] data) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
    Signature signature = Signature.getInstance(SIGNATURE_CIPHER, PROVIDER);

    signature.initSign(key, secureRandom);

    signature.update(data);

    return signature.sign();
  }

  public static boolean dsaVerify(PublicKey key, byte[] data, byte[] dataSignature) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
    Signature signature = Signature.getInstance(SIGNATURE_CIPHER, PROVIDER);

    signature.initVerify(key);

    signature.update(data);

    return signature.verify(dataSignature);
  }

  public static long generateRandomNonce() {
    return secureRandom.nextLong();
  }

  public static String generateRandomToken() {
    byte[] tokenBytes = new byte[TOKEN_SIZE];
    secureRandom.nextBytes(tokenBytes);

    return Base64.getEncoder().encodeToString(tokenBytes);
  }

  public static SecretKey getKeyFromBytes(byte[] encodedKey, String alg) {
    return new SecretKeySpec(encodedKey, 0, encodedKey.length, alg);
  }
}