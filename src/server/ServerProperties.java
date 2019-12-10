package server;

import com.google.gson.Gson;
import server.crypt.PKICommsManager;
import server.db.ServerDatabaseDriver;
import shared.errors.db.FailedToInsertException;
import shared.parameters.ServerParameterMap;
import shared.parameters.ServerParameter;
import server.props.ServerProperty;
import shared.errors.db.CriticalDatabaseException;
import shared.errors.db.DatabaseException;
import shared.errors.properties.PropertyException;
import shared.utils.GsonUtils;
import shared.utils.crypto.*;
import shared.utils.properties.CustomProperties;

import javax.crypto.spec.DHParameterSpec;
import javax.net.ssl.SSLContext;
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

  private String pubKeyName;
  private int pubKeySize;
  private String ksPassword;

  private int bufferSizeInMB;

  boolean PKI_ENABLED;
  volatile PKICommsManager PKI_COMMS_MGR;

  ServerProperties(CustomProperties properties, KSHelper ksHelper, ServerDatabaseDriver db, Logger logger, SSLContext sslContext) throws PropertyException, GeneralSecurityException, DatabaseException, CriticalDatabaseException {
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



    // check if supposed to reset server params and reset them if so
    if (properties.getBool(ServerProperty.PARAMS_RESET))
      resetParams(properties);

    // Configure PKI Comms manager if pki enabled
    PKI_ENABLED = properties.getBool(ServerProperty.USE_PKI);
    if (PKI_ENABLED)
      PKI_COMMS_MGR = new PKICommsManager(properties, sslContext, aeaHelper, logger);
  }

  private PrivateKey privateKey() throws GeneralSecurityException {
    return (PrivateKey) ksHelper.getKey(pubKeyName);
  }

  private void resetParams(CustomProperties props) throws GeneralSecurityException, DatabaseException, CriticalDatabaseException, PropertyException {
    // Delete all params
    DB.deleteAllParameters();

    // Create parameter list
    ServerParameterMap params = new ServerParameterMap();

    // Insert AEA parameters
    insertParameter(params, ServerParameter.PUB_KEY_ALG, aeaHelper.getKeyAlg());
    insertParameter(params, ServerParameter.CERT_SIG_ALG, aeaHelper.getCertAlg());

    // Generate DH Spec and insert DH parameters
    // Initialize DH params, generate DH Spec and insert DH parameters
    int dhKeySize = props.getInt(ServerProperty.DH_KEY_SIZE);
    String dhAlg = props.getString(ServerProperty.DH_KEY_ALG);
    DHHelper dhHelper = new DHHelper(dhAlg, dhKeySize);
    DHParameterSpec dhSpec = dhHelper.generateParams();

    insertParameter(params, ServerParameter.DH_ALG, dhAlg);
    insertParameter(params, ServerParameter.DH_P, dhSpec.getP().toString()); // Big Int
    insertParameter(params, ServerParameter.DH_G, dhSpec.getG().toString()); // Big Int
    insertParameter(params, ServerParameter.DH_KEYSIZE, String.valueOf(dhKeySize)); // int
    insertParameter(params, ServerParameter.DH_HASH_ALG,  props.getString(ServerProperty.DH_KEY_HASH_ALG));

    // Join all parameters, sign them, encode them and insert them in DB
    byte[] paramBytes = params.getAllParametersBytes();
    byte[] paramSigBytes = aeaHelper.sign(privateKey(), paramBytes);

    insertParameter(params, ServerParameter.PARAM_SIG, b64Helper.encode(paramSigBytes));
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
  private void insertParameter(ServerParameterMap params, ServerParameter type, String value) throws CriticalDatabaseException, FailedToInsertException {
    params.put(type, value);
    DB.insertParameter(type, value);
  }
}
