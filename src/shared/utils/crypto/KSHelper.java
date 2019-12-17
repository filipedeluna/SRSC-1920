package shared.utils.crypto;

import client.props.ClientProperty;
import shared.errors.crypto.InvalidPublicKeyException;
import shared.utils.Utils;
import shared.utils.crypto.util.DHKeyType;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStore.SecretKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class KSHelper {
  private SEAHelper seaHelper;
  private KeyStore store;

  private final String keyStoreLoc;
  private final char[] keyStorePass;
  private SecretKey seaKey;

  public KSHelper(String keyStoreLoc, String keyStoreType, char[] keyStorePass, boolean isTrustStore) throws IOException, GeneralSecurityException {
    this.keyStoreLoc = keyStoreLoc;
    this.keyStorePass = keyStorePass;

    // Load Keystore from file
    FileInputStream stream = new FileInputStream(keyStoreLoc);
    store = KeyStore.getInstance(keyStoreType);
    store.load(stream, keyStorePass);

    // use GCM to guarantee integrity when encrypting dh generated shared keys
    if (!isTrustStore) {
      seaHelper = new SEAHelper("AES/GCM/NoPadding");
      seaKey = seaHelper.getKeyFromBytes(seaHelper.trimKeyToAlg(String.valueOf(keyStorePass).getBytes()));
    }
  }

  public Key getKey(String keyName) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
    return store.getKey(keyName, keyStorePass);
  }

  public void saveDHKeyPair(String username, DHKeyType type, KeyPair keyPair) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException, IOException, InvalidAlgorithmParameterException {
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
    Files.deleteIfExists(filePath);
    Files.write(filePath, fileBytesEncrypted);
  }

  public KeyPair loadDHKeyPair(String username, DHKeyType type) throws IOException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, InvalidAlgorithmParameterException, ClassNotFoundException {
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

  public void saveSharedKey(int clientId, int destinationId, DHKeyType type, SecretKey key, char[] pass) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
    SecretKeyEntry seaKeyEntry = new SecretKeyEntry(key);
    ProtectionParameter protectionParam = new KeyStore.PasswordProtection(pass);
    String keyName = clientId + "-" + destinationId + "-" + type.getVal() + "shared";

    store.deleteEntry(keyName);
    store.setEntry(keyName, seaKeyEntry, protectionParam);
    store.store(new FileOutputStream(keyStoreLoc), pass);
  }

  public Key getSharedKey(int clientId, int destinationId, DHKeyType type, char[] pass) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
    return store.getKey(clientId + "-" + destinationId + "-" + type.getVal() + "shared", pass);
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

  public void saveKeyPair(KeyPair keyPair, Certificate[] chain, String keyName, char[] pass) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
    PrivateKeyEntry keyEntry = new PrivateKeyEntry(keyPair.getPrivate(), chain);
    ProtectionParameter protectionParam = new KeyStore.PasswordProtection(pass);

    store.deleteEntry(keyName);
    store.setEntry(keyName, keyEntry, protectionParam);
    store.store(new FileOutputStream(keyStoreLoc), pass);
  }

  /*
    UTILS
  */

  private Path getDHKeyPairPath(String username, DHKeyType type) {
    String ksFolderPath = Paths.get(keyStoreLoc).toAbsolutePath().getParent().toString();
    return Paths.get(ksFolderPath + "/keys/" + username + "-" + type);
  }

}
