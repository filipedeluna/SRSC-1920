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

  HashHelper hashHelper;
  AEAHelper aeaHelper;
  B64Helper b64Helper;
  Gson GSON;
  final KSHelper ksHelper;
  final Logger logger;

  PKIDatabaseDriver DB;

  PublicKey PUB_KEY;
  X509Certificate CERT;
  int CERT_VALIDITY;

  private String pubKeyName;
  private String token;
  private int pubKeySize;

  PKIServerProperties(CustomProperties props, PKIDatabaseDriver db, Logger logger, KSHelper ksHelper) throws PropertyException, GeneralSecurityException {
    this.ksHelper = ksHelper;
    this.logger = logger;
    DEBUG_MODE = props.getBool(PKIProperty.DEBUG);
    DB = db;
    b64Helper = new B64Helper();
    GSON = GsonUtils.buildGsonInstance();

    token = props.getString(PKIProperty.TOKEN_VALUE);

    // Initialize hash helper
    hashHelper = new HashHelper(props.getString(PKIProperty.HASH_ALG));

    // Initialize AEA params
    String pubKeyAlg = props.getString(PKIProperty.PUB_KEY_ALG);
    String certSignAlg = props.getString(PKIProperty.CERT_SIGN_ALG);
    pubKeySize = props.getInt(PKIProperty.PUB_KEY_SIZE);
    aeaHelper = new AEAHelper(pubKeyAlg, certSignAlg);

    // Get pub key and assign it
    pubKeyName = props.getString(PKIProperty.PKI_PUB_KEY);
    CERT = ksHelper.getCertificate(pubKeyName);
    PUB_KEY = CERT.getPublicKey();
    CERT_VALIDITY = props.getInt(PKIProperty.CERTIFICATE_VALIDITY);
  }

  PrivateKey privateKey() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
    return (PrivateKey) ksHelper.getKey(pubKeyName);
  }

  boolean isTokenValid(String token) {
    return this.token.equals(token);
  }

  public int getPubKeySize() {
    return pubKeySize;
  }
}
