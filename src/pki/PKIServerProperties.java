package pki;

import com.google.gson.Gson;
import pki.db.PKIDatabaseDriver;
import pki.props.PKIProperty;
import shared.errors.properties.PropertyException;
import shared.utils.GsonUtils;
import shared.utils.crypto.*;
import shared.utils.properties.CustomProperties;

import java.security.*;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

final class PKIServerProperties {
  boolean DEBUG_MODE;

  HashHelper HASH;
  AEAHelper AEA;
  B64Helper B64;
  Gson GSON;
  final Logger LOGGER;

  PKIDatabaseDriver DB;

  PublicKey PUB_KEY;
  X509Certificate CERT;
  int CERT_VALIDITY;

  private KeyStore keyStore;
  private RNDHelper random;

  private String pubKeyName;
  private String ksPassword;
  private String token;

  PKIServerProperties(CustomProperties props, KeyStore keyStore, PKIDatabaseDriver db, Logger logger) throws PropertyException, GeneralSecurityException {
    LOGGER = logger;
    DEBUG_MODE = props.getBool(PKIProperty.DEBUG);
    this.keyStore = keyStore;
    DB = db;
    B64 = new B64Helper();
    GSON = GsonUtils.buildGsonInstance();
    random = new RNDHelper();

    token = props.getString(PKIProperty.TOKEN_VALUE);

    // Get and set password for keystore
    ksPassword = props.getString(PKIProperty.KEYSTORE_PASS);

    // Initialize hash helper
    HASH = new HashHelper(props.getString(PKIProperty.HASH_ALG), B64);

    // Initialize AEA params
    String pubKeyAlg = props.getString(PKIProperty.PUB_KEY_ALG);
    String certSignAlg = props.getString(PKIProperty.CERT_SIGN_ALG);
    String certFormat = props.getString(PKIProperty.CERT_FORMAT);
    int pubKeySize = props.getInt(PKIProperty.PUB_KEY_SIZE);
    AEA = new AEAHelper(pubKeyAlg, certSignAlg, certFormat, pubKeySize, random);

    // Get pub key and assign it
    pubKeyName = props.getString(PKIProperty.PKI_PUB_KEY);
    CERT = AEA.getCertFromKeystore(pubKeyName, keyStore);
    PUB_KEY = CERT.getPublicKey();
    CERT_VALIDITY = props.getInt(PKIProperty.CERTIFICATE_VALIDITY);
  }

  PrivateKey privateKey() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
    return (PrivateKey) keyStore.getKey(pubKeyName, ksPassword.toCharArray());
  }

  boolean isTokenValid(String token) {
    return this.token.equals(token);
  }
}
