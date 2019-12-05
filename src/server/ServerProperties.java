package server;

import com.google.gson.Gson;
import server.crypt.PKICommunicationsManager;
import server.db.ServerDatabaseDriver;
import server.db.ServerParameterMap;
import server.db.ServerParameterType;
import server.errors.parameters.ParameterException;
import server.props.ServerProperty;
import shared.errors.db.CriticalDatabaseException;
import shared.errors.db.DatabaseException;
import shared.errors.properties.PropertyException;
import shared.utils.GsonUtils;
import shared.utils.crypto.AEAHelper;
import shared.utils.crypto.B4Helper;
import shared.utils.crypto.DHHelper;
import shared.utils.crypto.HashHelper;
import shared.utils.properties.CustomProperties;

import javax.crypto.spec.DHParameterSpec;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.*;
import java.util.logging.Logger;

final class ServerProperties {
  boolean DEBUG_MODE;

  DHHelper DH;
  HashHelper HASH;
  AEAHelper AEA;
  B4Helper B64;
  Gson GSON;
  Logger LOGGER;

  ServerDatabaseDriver DB;

  PublicKey PUB_KEY;

  private KeyStore keyStore;

  private CustomProperties props;
  private String pubKeyName;
  private String ksPassword;

  private int bufferSizeInMB;

  boolean PKI_ENABLED;
  volatile PKICommunicationsManager PKI_COMMS_MGR;

  ServerProperties(CustomProperties properties, KeyStore keyStore, ServerDatabaseDriver db, Logger logger, SSLContext sslContext) throws PropertyException, GeneralSecurityException, IOException, DatabaseException, CriticalDatabaseException, ParameterException {
    this.props = properties;
    this.keyStore = keyStore;

    // Set Debug mode
    DEBUG_MODE = properties.getBool(ServerProperty.DEBUG);

    // Max size of socket buffer
    bufferSizeInMB = properties.getInt(ServerProperty.BUFFER_SIZE_MB);

    B64 = new B4Helper();
    GSON = GsonUtils.buildGsonInstance();
    DB = db;
    LOGGER = logger;

    // Configure PKI Comms manager if pki enabled
    PKI_ENABLED = properties.getBool(ServerProperty.USE_PKI);
    if (PKI_ENABLED)
      PKI_COMMS_MGR = new PKICommunicationsManager(properties, sslContext, GSON, logger);

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
    PUB_KEY = AEA.getCertFromKeystore(pubKeyName, this.keyStore).getPublicKey();

    // Initialize DH params and helper
    String dhKeyAlg = properties.getString(ServerProperty.DH_KEY_ALG);
    String dhKeyHashAlg = properties.getString(ServerProperty.DH_KEY_HASH_ALG);
    int dhKeySize = properties.getInt(ServerProperty.DH_KEY_SIZE);
    DH = new DHHelper(dhKeyAlg, dhKeyHashAlg, dhKeySize);

    // check if supposed to reset server params and reset them if so
    if (properties.getBool(ServerProperty.PARAMS_RESET))
      paramsReset();
  }

  PrivateKey privateKey() throws GeneralSecurityException {
    return (PrivateKey) keyStore.getKey(pubKeyName, ksPassword.toCharArray());
  }

  private void paramsReset() throws GeneralSecurityException, DatabaseException, CriticalDatabaseException, IOException, ParameterException {
    // Delete all params
    DB.deleteAllParameters();

    // Create parameter list
    ServerParameterMap params = new ServerParameterMap();

    // Insert AEA parameters
    params.put(ServerParameterType.PUB_KEY_ALG, AEA.keyAlg());
    params.put(ServerParameterType.CERT_SIG_ALG, AEA.certAlg());

    // Generate DH Spec and insert DH parameters
    DHParameterSpec spec = DH.genParams();
    params.put(ServerParameterType.DH_ALG, DH.alg());
    params.put(ServerParameterType.DH_P, spec.getP().toString()); // Big Int
    params.put(ServerParameterType.DH_G, spec.getG().toString()); // Big Int
    params.put(ServerParameterType.DH_KEYSIZE, String.valueOf(DH.keySize())); // int
    params.put(ServerParameterType.DH_HASH_ALG, DH.hashAlg());

    // Join all parameters, sign them, encode them and insert them in DB
    DB.insertParameter(ServerParameterType.PARAM_SIG, B64.encode(params.getAllParametersBytes()));
  }

  public int getBufferSizeInMB() {
    return bufferSizeInMB;
  }
}
