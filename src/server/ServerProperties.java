package server;

import com.google.gson.Gson;
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
import java.security.*;

class ServerProperties {
  boolean DEBUG_MODE;

  DHHelper DH;
  HashHelper HASH;
  AEAHelper AEA;
  B4Helper B64;
  Gson GSON;

  ServerDatabaseDriver DB;
  KeyStore KEYSTORE;

  PublicKey PUB_KEY;

  private CustomProperties props;
  private String pubKeyName;
  private String ksPassword;

  ServerProperties(CustomProperties properties, KeyStore keyStore, ServerDatabaseDriver db) throws PropertyException, GeneralSecurityException, IOException, DatabaseException, CriticalDatabaseException {
    this.props = properties;

    DEBUG_MODE = properties.getBool(ServerProperty.DEBUG);
    KEYSTORE = keyStore;
    DB = db;

    B64 = new B4Helper();
    GSON = GsonUtils.buildGsonInstance();

    // Get and set password for keystore
    ksPassword = props.getString(ServerProperty.KEYSTORE_PASS);

    // Initialize hash helper
    HASH = new HashHelper(properties.getString(ServerProperty.HASH_ALG));

    // Initialize AEA params
    String pubKeyAlg = properties.getString(ServerProperty.PUB_KEY_ALG);
    String certSignAlg = properties.getString(ServerProperty.CERT_SIGN_ALG);
    int pubKeySize = properties.getInt(ServerProperty.PUB_KEY_SIZE);
    AEA = new AEAHelper(pubKeyAlg, certSignAlg, pubKeySize);

    // Get pub key and assign it
    pubKeyName = properties.getString(ServerProperty.PUB_KEY_NAME);
    PUB_KEY = AEA.getCertFromKeystore(pubKeyName, KEYSTORE).getPublicKey();

    // Initialize DH params
    String dhKeyAlg = properties.getString(ServerProperty.DH_KEY_ALG);
    String dhKeyHashAlg = properties.getString(ServerProperty.DH_KEY_HASH_ALG);
    int dhKeySize = properties.getInt(ServerProperty.DH_KEY_SIZE);

    // Initialize dh helper with params and check if supposed to reset dh params
    boolean dhParamsReset = properties.getBool(ServerProperty.PARAMS_RESET);
    DH = new DHHelper(dhKeyAlg, dhKeyHashAlg, dhKeySize);

    if (dhParamsReset)
      dhParamsReset();
  }

  PrivateKey privateKey() throws GeneralSecurityException {
    return (PrivateKey) KEYSTORE.getKey(pubKeyName, ksPassword.toCharArray());
  }

  private void dhParamsReset() throws GeneralSecurityException, DatabaseException, CriticalDatabaseException, IOException {
    // Generate and get DH parameters
    DHParameterSpec spec = DH.genParams();
    String dhAlg = DH.alg();
    String p = spec.getP().toString(); // Big int
    String g = spec.getG().toString(); // Big int
    String keySize = String.valueOf(DH.keySize()); // int

    // Insert DH parameters
    DB.insertParameter(ServerParameter.DH_ALG, dhAlg);
    DB.insertParameter(ServerParameter.DH_P, p);
    DB.insertParameter(ServerParameter.DH_G, g);
    DB.insertParameter(ServerParameter.DH_KS, keySize);

    // Join all parameters and sign them
    byte[] dhParamsBytes = CryptUtil.joinByteArrays(
        dhAlg.getBytes(),
        p.getBytes(),
        g.getBytes(),
        keySize.getBytes()
    );


  }
}
