package shared.utils.crypto;

import client.crypt.DHKeyType;
import shared.errors.crypto.InvalidPublicKeyException;
import shared.utils.Utils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHPublicKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class KSHelper {
  private SEAHelper seaHelper;
  private KeyStore store;

  private KeyFactory keyFactory;
  private String keyStoreLoc;
  private char[] keyStorePass;
  private SecretKey seaKey;

  public KSHelper(String keyStoreLoc, String keyStoreType, char[] keyStorePass, boolean isTrustStore) throws IOException, GeneralSecurityException {
    this.keyStoreLoc = keyStoreLoc;
    this.keyStorePass = keyStorePass;

    // Load Keystore from file
    FileInputStream stream = new FileInputStream(keyStoreLoc);
    store = KeyStore.getInstance(keyStoreType);
    store.load(stream, keyStorePass);

    // Create sea Helper for storing keypairs, use GCM to guarantee integrity
    if (!isTrustStore) {
      keyFactory = KeyFactory.getInstance("DH", "BC");
      seaHelper = new SEAHelper("AES", "GCM", "NoPadding");
      seaKey = seaHelper.getKeyFromBytes(seaHelper.trimKeyToAlg(String.valueOf(keyStorePass).getBytes()));
    }
  }

  public Key getKey(String keyName) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
    return store.getKey(keyName, keyStorePass);
  }

  public boolean hasSEAsharedInKeystore(String alias) {
    try {
      store.getKey(alias, keyStorePass);
      return true;
    } catch (UnrecoverableKeyException ex) {
      ex.printStackTrace();
    } catch (Exception e) {
      e.printStackTrace();
    }
    return false;
  }

  public void saveDHKeyPair(String username, DHKeyType type, KeyPair keyPair, BigInteger p, BigInteger g) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException, IOException, InvalidAlgorithmParameterException {
    // Generate IV and decode private key, public and the params
    byte[] iv = seaHelper.generateIV();

    // Write as file to byte stream
    ByteArrayOutputStream byteOutput = new ByteArrayOutputStream();
    ObjectOutputStream objectOutput = new ObjectOutputStream(byteOutput);

    objectOutput.writeObject(keyPair);

    objectOutput.flush();

    // Get whole bytestream and encrypt with GCM to preserve integrity
    byte[] fileBytesEncrypted = seaHelper.encrypt(byteOutput.toByteArray(), seaKey, iv);
    objectOutput.close();

    fileBytesEncrypted = Utils.joinByteArrays(iv, fileBytesEncrypted);

    // Write bytes to file
    Path filePath = getDHKeyPairPath(username, type);
    // Files.deleteIfExists(getDHKeyPairPath(uuid)); // TODO decide if we should use this
    Files.write(filePath, fileBytesEncrypted);
  }

  public KeyPair loadDHKeyPair(String username, DHKeyType type) throws IOException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, InvalidKeySpecException, InvalidAlgorithmParameterException, ClassNotFoundException {
    // Read encrypted bytes from file
    byte[] fileBytesEncrypted = Files.readAllBytes(getDHKeyPairPath(username, type));
    // Get the iv
    byte[] iv = Arrays.copyOfRange(fileBytesEncrypted, 0, seaHelper.ivSize());
    fileBytesEncrypted = Arrays.copyOfRange(fileBytesEncrypted, seaHelper.ivSize(), fileBytesEncrypted.length);
    byte[] fileBytes = seaHelper.decrypt(fileBytesEncrypted, seaKey, iv);

    // Read keypair from the input stream
    ObjectInputStream objectInput = new ObjectInputStream(new ByteArrayInputStream((fileBytes)));

    KeyPair keyPair = (KeyPair) objectInput.readObject();
    objectInput.close();

    return keyPair;
  }

  public boolean dhKeyPairExists(String username, DHKeyType type) {
    return Files.exists(getDHKeyPairPath(username, type)) || !Files.notExists(getDHKeyPairPath(username, type));
  }

  public X509Certificate getCertificate(String alias) throws KeyStoreException {
    return (X509Certificate) store.getCertificate(alias);
  }

  public PublicKey getPublicKey(String alias) throws KeyStoreException {
    return store.getCertificate(alias).getPublicKey();
  }

  public static KeyPair getKeyPair(KeyStore ks, char[] pass, String keyAlias) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, InvalidPublicKeyException {
    Key privateKey = ks.getKey(keyAlias, pass);

    Certificate cert = ks.getCertificate(keyAlias);

    PublicKey publicKey = cert.getPublicKey();

    if (!(privateKey instanceof PrivateKey))
      throw new InvalidPublicKeyException();

    return new KeyPair(publicKey, (PrivateKey) privateKey);
  }

  public KeyStore getStore() {
    return store;
  }

  public KeyManagerFactory getKeyManagerFactory() throws GeneralSecurityException {
    KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
    keyManagerFactory.init(store, keyStorePass);

    return keyManagerFactory;
  }

  public TrustManagerFactory getTrustManagerFactory() throws GeneralSecurityException {
    TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
    trustManagerFactory.init(store);

    return trustManagerFactory;
  }

  /*
    UTILS
  */

  private Path getDHKeyPairPath(String username, DHKeyType type) {
    return Paths.get("src/client/crypt/keys/" + username + "-" + type.getVal());
  }

}
