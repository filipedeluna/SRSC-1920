package client;

import client.props.ClientProperty;
import com.google.gson.Gson;
import server.db.ServerDatabaseDriver;
import server.db.ServerParameterMap;
import server.db.ServerParameterType;
import server.errors.parameters.ParameterException;
import server.props.ServerProperty;
import shared.errors.db.CriticalDatabaseException;
import shared.errors.db.DatabaseException;
import shared.errors.properties.PropertyException;
import shared.utils.GsonUtils;
import shared.utils.crypto.*;
import shared.utils.properties.CustomProperties;

import javax.crypto.spec.DHParameterSpec;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

final class ClientProperties {

  DHHelper DH;
  HashHelper HASH;
  AEAHelper AEA;
  B64Helper B64;
  Gson GSON;
  PublicKey PUB_KEY;
  private KeyStore keyStore;
  private KeyStore tstore;
  private CustomProperties props;
  private String pubKeyName;
  private String ksPassword;
  private String tsPassword;
  private int bufferSizeInMB;
  RNDHelper rndHelper;

  ClientProperties(CustomProperties properties, KeyStore keyStore, KeyStore tstore) throws PropertyException, GeneralSecurityException, IOException, DatabaseException, CriticalDatabaseException, ParameterException {
    this.props = properties;
    this.keyStore = keyStore;
    this.tstore = tstore;
    RNDHelper rndHelper = new RNDHelper();

    bufferSizeInMB = properties.getInt(ClientProperty.BUFFER_SIZE_MB);


    B64 = new B64Helper();
    GSON = GsonUtils.buildGsonInstance();

    // Get and set password for keystore
    ksPassword = props.getString(ClientProperty.KEYSTORE_PASS);

    // Initialize hash helper

    // Initialize AEA params
    String pubKeyAlg = properties.getString(ClientProperty.PUB_KEY_ALG);
    String certSignAlg = properties.getString(ClientProperty.CERT_SIGN_ALG);
    int pubKeySize = properties.getInt(ClientProperty.PUB_KEY_SIZE);
    String certformat= properties.getString(ClientProperty.CERT_FORMAT);
    String provider = properties.getString(ClientProperty.PROVIDER);
    AEA = new AEAHelper(pubKeyAlg, certSignAlg,certformat, pubKeySize, provider);

    // Get pub key and assign it
    pubKeyName = properties.getString(ClientProperty.PUB_KEY_NAME);
    PUB_KEY = AEA.getCertFromKeystore(pubKeyName, this.keyStore).getPublicKey();

    // Initialize DH params and helper

    // check if supposed to reset server params and reset them if so

  }

  PrivateKey privateKey() throws GeneralSecurityException {
    return (PrivateKey) keyStore.getKey(pubKeyName, ksPassword.toCharArray());
  }

  public RNDHelper getRndHelper() {
    return rndHelper;
  }

  public int getBufferSizeInMB() {
    return bufferSizeInMB;
  }

}
