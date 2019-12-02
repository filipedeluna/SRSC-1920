package pki;

import com.google.gson.Gson;
import pki.db.PKIDatabaseDriver;
import pki.props.PKIProperty;
import server.db.ServerDatabaseDriver;
import server.db.ServerParameter;
import server.props.ServerProperty;
import shared.errors.db.CriticalDatabaseException;
import shared.errors.db.DatabaseException;
import shared.errors.properties.PropertyException;
import shared.utils.CryptUtil;
import shared.utils.GsonUtils;
import shared.utils.crypto.AEAHelper;
import shared.utils.crypto.B4Helper;
import shared.utils.crypto.DHHelper;
import shared.utils.crypto.HashHelper;
import shared.utils.properties.CustomProperties;

import javax.crypto.spec.DHParameterSpec;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

class PKIServerProperties {
  boolean DEBUG_MODE;

  DHHelper DH;
  HashHelper HASH;
  AEAHelper AEA;
  B4Helper B64;
  Gson GSON;

  PKIDatabaseDriver DB;
  KeyStore KEYSTORE;

  PublicKey PUB_KEY;
  X509Certificate CERT;
  int CERT_VALIDATY;

  private CustomProperties props;
  private String pubKeyName;
  private String ksPassword;
  private String token;

  PKIServerProperties(CustomProperties props, KeyStore keyStore, PKIDatabaseDriver db) throws PropertyException, GeneralSecurityException {
    this.props = props;

    DEBUG_MODE = props.getBool(ServerProperty.DEBUG);
    KEYSTORE = keyStore;
    DB = db;

    B64 = new B4Helper();
    GSON = GsonUtils.buildGsonInstance();

    token = props.getString(PKIProperty.TOKEN_VALUE);

    // Get and set password for keystore
    ksPassword = props.getString(PKIProperty.KEYSTORE_PASS);

    // Initialize hash helper
    HASH = new HashHelper(props.getString(PKIProperty.HASH_ALG));

    // Initialize AEA params
    String pubKeyAlg = props.getString(PKIProperty.PUB_KEY_ALG);
    String certSignAlg = props.getString(PKIProperty.CERT_SIGN_ALG);
    int pubKeySize = props.getInt(PKIProperty.PUB_KEY_SIZE);
    AEA = new AEAHelper(pubKeyAlg, certSignAlg, pubKeySize);

    // Get pub key and assign it
    pubKeyName = props.getString(PKIProperty.PKI_PUB_KEY);
    CERT = AEA.getCertFromKeystore(pubKeyName, KEYSTORE);
    PUB_KEY = CERT.getPublicKey();
    CERT_VALIDATY = props.getInt(PKIProperty.CERTIFICATE_VALIDITY);
  }

  PrivateKey privateKey() throws GeneralSecurityException {
    return (PrivateKey) KEYSTORE.getKey(pubKeyName, ksPassword.toCharArray());
  }

  boolean validToken(String token) {
    return this.token.equals(token);
  }
}
