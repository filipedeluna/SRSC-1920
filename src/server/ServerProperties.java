package server;

import com.google.gson.Gson;
import server.crypt.PKICommsManager;
import server.db.ServerDatabaseDriver;
import shared.errors.db.FailedToInsertException;
import shared.parameters.ServerParameterMap;
import shared.parameters.ServerParameterType;
import server.errors.ParameterException;
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

  AEAHelper aeaHelper;
  B64Helper b64Helper;
  Gson GSON;
  Logger logger;
  KSHelper ksHelper;

  ServerDatabaseDriver DB;

  private DHHelper dhHelper;

  private String pubKeyName;
  private int pubKeySize;
  private String ksPassword;

  private int bufferSizeInMB;

  boolean PKI_ENABLED;
  volatile PKICommsManager PKI_COMMS_MGR;

  ServerProperties(CustomProperties properties, KSHelper ksHelper, ServerDatabaseDriver db, Logger logger, SSLContext sslContext) throws PropertyException, GeneralSecurityException, IOException, DatabaseException, CriticalDatabaseException, ParameterException {
    this.ksHelper = ksHelper;

    // Set Debug mode
    DEBUG_MODE = properties.getBool(ServerProperty.DEBUG);

    // Max size of socket buffer
    bufferSizeInMB = properties.getInt(ServerProperty.BUFFER_SIZE_MB);

    b64Helper = new B64Helper();
    GSON = GsonUtils.buildGsonInstance();
    DB = db;
    this.logger = logger;

    // Get and set password for keystore
    ksPassword = properties.getString(ServerProperty.KEYSTORE_PASS);

    // Initialize AEA params
    String pubKeyAlg = properties.getString(ServerProperty.PUB_KEY_ALG);
    String certSignAlg = properties.getString(ServerProperty.CERT_SIGN_ALG);
    pubKeySize = properties.getInt(ServerProperty.PUB_KEY_SIZE);
    aeaHelper = new AEAHelper(pubKeyAlg, certSignAlg);

    // Get pub key and assign it
    pubKeyName = properties.getString(ServerProperty.PUB_KEY_NAME);

    // Initialize DH params and helper
    String dhKeyAlg = properties.getString(ServerProperty.DH_KEY_ALG);
    String dhKeyHashAlg = properties.getString(ServerProperty.DH_KEY_HASH_ALG);
    int dhKeySize = properties.getInt(ServerProperty.DH_KEY_SIZE);
    dhHelper = new DHHelper(dhKeyAlg, dhKeyHashAlg, dhKeySize);

    // check if supposed to reset server params and reset them if so
    if (properties.getBool(ServerProperty.PARAMS_RESET))
      resetParams();

    // Configure PKI Comms manager if pki enabled
    PKI_ENABLED = properties.getBool(ServerProperty.USE_PKI);
    if (PKI_ENABLED)
      PKI_COMMS_MGR = new PKICommsManager(properties, sslContext, aeaHelper, logger);
  }

  private PrivateKey privateKey() throws GeneralSecurityException {
    return (PrivateKey) ksHelper.getKey(pubKeyName);
  }

  private void resetParams() throws GeneralSecurityException, DatabaseException, CriticalDatabaseException, IOException, ParameterException {
    // Delete all params
    DB.deleteAllParameters();

    // Create parameter list
    ServerParameterMap params = new ServerParameterMap();

    // Insert AEA parameters
    insertParameter(params, ServerParameterType.PUB_KEY_ALG, aeaHelper.getKeyAlg());
    insertParameter(params, ServerParameterType.CERT_SIG_ALG, aeaHelper.getCertAlg());

    // Generate DH Spec and insert DH parameters
    DHParameterSpec spec = dhHelper.genParams();
    insertParameter(params, ServerParameterType.DH_ALG, dhHelper.getAlgorithm());
    insertParameter(params, ServerParameterType.DH_P, spec.getP().toString()); // Big Int
    insertParameter(params, ServerParameterType.DH_G, spec.getG().toString()); // Big Int
    insertParameter(params, ServerParameterType.DH_KEYSIZE, String.valueOf(dhHelper.getKeySize())); // int
    insertParameter(params, ServerParameterType.DH_HASH_ALG, dhHelper.getHashAlgorithm());

    // Join all parameters, sign them, encode them and insert them in DB
    byte[] paramBytes = params.getAllParametersBytes();
    byte[] paramSigBytes = aeaHelper.sign(privateKey(), paramBytes);

    insertParameter(params, ServerParameterType.PARAM_SIG, b64Helper.encode(paramSigBytes));
  }

  public int getBufferSizeInMB() {
    return bufferSizeInMB;
  }

  public int getPubKeySize() {
    return pubKeySize;
  }

  /*
      Utils
    */
  private void insertParameter(ServerParameterMap params, ServerParameterType type, String value) throws CriticalDatabaseException, FailedToInsertException {
    params.put(type, value);
    DB.insertParameter(type, value);
  }
}
