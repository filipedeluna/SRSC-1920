package server;

import com.google.gson.Gson;
import server.crypt.PKICommsManager;
import server.db.ServerDatabaseDriver;
import shared.parameters.ServerParameterMap;
import shared.parameters.ServerParameterType;
import server.errors.parameters.ParameterException;
import server.props.ServerProperty;
import shared.errors.db.CriticalDatabaseException;
import shared.errors.db.DatabaseException;
import shared.errors.properties.PropertyException;
import shared.utils.GsonUtils;
import shared.utils.crypto.*;
import shared.utils.properties.CustomProperties;

import javax.crypto.spec.DHParameterSpec;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.*;
import java.util.logging.Logger;

final class ServerProperties {
  boolean DEBUG_MODE;

  AEAHelper AEA;
  B64Helper B64;
  Gson GSON;
  Logger LOGGER;

  ServerDatabaseDriver DB;

  private final KeyStore keyStore;
  private DHHelper dhHelper;

  private String pubKeyName;
  private String ksPassword;

  private int bufferSizeInMB;

  boolean PKI_ENABLED;
  volatile PKICommsManager PKI_COMMS_MGR;

  ServerProperties(CustomProperties properties, KeyStore keyStore, ServerDatabaseDriver db, Logger logger, SSLContext sslContext) throws PropertyException, GeneralSecurityException, IOException, DatabaseException, CriticalDatabaseException, ParameterException {
    this.keyStore = keyStore;

    // Set Debug mode
    DEBUG_MODE = properties.getBool(ServerProperty.DEBUG);

    // Max size of socket buffer
    bufferSizeInMB = properties.getInt(ServerProperty.BUFFER_SIZE_MB);

    B64 = new B64Helper();
    GSON = GsonUtils.buildGsonInstance();
    DB = db;
    LOGGER = logger;

    // Get and set password for keystore
    ksPassword = properties.getString(ServerProperty.KEYSTORE_PASS);

    // Get provider
    String provider = properties.getString(ServerProperty.PROVIDER);

    // Initialize AEA params
    String pubKeyAlg = properties.getString(ServerProperty.PUB_KEY_ALG);
    String certSignAlg = properties.getString(ServerProperty.CERT_SIGN_ALG);
    int pubKeySize = properties.getInt(ServerProperty.PUB_KEY_SIZE);
    AEA = new AEAHelper(pubKeyAlg, certSignAlg, pubKeySize, provider);

    // Get pub key and assign it
    pubKeyName = properties.getString(ServerProperty.PUB_KEY_NAME);

    // Initialize DH params and helper
    String dhKeyAlg = properties.getString(ServerProperty.DH_KEY_ALG);
    String dhKeyHashAlg = properties.getString(ServerProperty.DH_KEY_HASH_ALG);
    int dhKeySize = properties.getInt(ServerProperty.DH_KEY_SIZE);
    dhHelper = new DHHelper(dhKeyAlg, dhKeyHashAlg, dhKeySize, provider);

    // check if supposed to reset server params and reset them if so
    if (properties.getBool(ServerProperty.PARAMS_RESET))
      resetParams();

    // Configure PKI Comms manager if pki enabled
    PKI_ENABLED = properties.getBool(ServerProperty.USE_PKI);
    if (PKI_ENABLED)
      PKI_COMMS_MGR = new PKICommsManager(properties, sslContext, AEA, logger);

  }

  private PrivateKey privateKey() throws GeneralSecurityException {
    return (PrivateKey) keyStore.getKey(pubKeyName, ksPassword.toCharArray());
  }

  private void resetParams() throws GeneralSecurityException, DatabaseException, CriticalDatabaseException, IOException, ParameterException {
    // Delete all params
    DB.deleteAllParameters();

    // Create parameter list
    ServerParameterMap params = new ServerParameterMap();

    // Insert AEA parameters
    params.put(ServerParameterType.PUB_KEY_ALG, AEA.getKeyAlg());
    params.put(ServerParameterType.CERT_SIG_ALG, AEA.getCertAlg());

    // Generate DH Spec and insert DH parameters
    DHParameterSpec spec = dhHelper.genParams();
    params.put(ServerParameterType.DH_ALG, dhHelper.getAlgorithm());
    params.put(ServerParameterType.DH_P, spec.getP().toString()); // Big Int
    params.put(ServerParameterType.DH_G, spec.getG().toString()); // Big Int
    params.put(ServerParameterType.DH_KEYSIZE, String.valueOf(dhHelper.getKeySize())); // int
    params.put(ServerParameterType.DH_HASH_ALG, dhHelper.getHashAlgorithm());

    // Join all parameters, sign them, encode them and insert them in DB
    byte[] paramBytes = params.getAllParametersBytes();
    byte[] paramSigBytes = AEA.sign(privateKey(), paramBytes);

    DB.insertParameter(ServerParameterType.PARAM_SIG, B64.encode(paramSigBytes));
  }

  public int getBufferSizeInMB() {
    return bufferSizeInMB;
  }
}
