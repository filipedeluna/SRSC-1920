package client;

import client.cache.ClientCacheController;
import client.crypt.ClientDHHelper;
import client.props.ClientProperty;
import com.google.gson.Gson;
import shared.errors.properties.PropertyException;
import shared.parameters.ServerParameterMap;
import shared.parameters.ServerParameterType;
import shared.utils.GsonUtils;
import shared.utils.crypto.*;
import shared.utils.properties.CustomProperties;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

final class ClientProperties {
  final String PROVIDER;

  final B64Helper B64Helper;
  final RNDHelper RNDHelper;
  final Gson GSON;
  final ClientCacheController CACHE;

  final KeyStore KEYSTORE;
  final KeyStore TRUSTSTORE;
  final String KEYSTORE_LOC;

  final String SEASPEC;

  AEAHelper AEAHelper;
  PublicKey PUB_KEY;
  ClientDHHelper DHHelper;

  private CustomProperties props;

  private int bufferSizeInMB;
  private String pubKeyName;

  ClientProperties(CustomProperties props, KeyStore keyStore, KeyStore trustStore) throws PropertyException, GeneralSecurityException {
    this.props = props;
    KEYSTORE = keyStore;
    TRUSTSTORE = trustStore;

    B64Helper = new B64Helper();
    RNDHelper = new RNDHelper();
    GSON = GsonUtils.buildGsonInstance();

    // System props
    CACHE= new ClientCacheController(props.getInt(ClientProperty.CACHE_SIZE));
    bufferSizeInMB = props.getInt(ClientProperty.BUFFER_SIZE_MB);

    // Crypt props
    PROVIDER = props.getString(ClientProperty.PROVIDER);
    SEASPEC = props.getString(ClientProperty.SEASPEC);
    KEYSTORE_LOC = props.getString(ClientProperty.KEYSTORE_LOC);
  }

  // Initialize AEAHelper
  void initAEAHelper(ServerParameterMap serverParams) throws GeneralSecurityException, PropertyException {
    String pubKeyAlg = serverParams.getParameter(ServerParameterType.PUB_KEY_ALG);
    String certSignAlg = serverParams.getParameter(ServerParameterType.CERT_SIG_ALG);
    int pubKeySize = Integer.parseInt(serverParams.getParameter(ServerParameterType.CERT_SIG_ALG));

    AEAHelper = new AEAHelper(pubKeyAlg, certSignAlg, pubKeySize, PROVIDER);

    // Get pub key and assign it
    pubKeyName = props.getString(ClientProperty.PUB_KEY_NAME);
    PUB_KEY = AEAHelper.getCertFromKeystore(pubKeyName, KEYSTORE).getPublicKey();
  }

  // Initialize DHHelper
  void initDHHelper(ServerParameterMap serverParams) throws GeneralSecurityException {
    String dhAlg = serverParams.getParameter(ServerParameterType.DH_ALG);
    String dhP = serverParams.getParameter(ServerParameterType.DH_P);
    String dhG = serverParams.getParameter(ServerParameterType.DH_G);
    int dhKeySize = Integer.parseInt(serverParams.getParameter(ServerParameterType.DH_KEYSIZE));
    String dhHashAlg = serverParams.getParameter(ServerParameterType.DH_HASH_ALG);

    DHHelper = new ClientDHHelper(dhAlg, dhHashAlg, dhKeySize, dhP, dhG, PROVIDER);
  }

  PrivateKey privateKey() throws GeneralSecurityException, PropertyException {
    return (PrivateKey) KEYSTORE.getKey(pubKeyName, keyStorePassword());
  }

  char[] keyStorePassword() throws PropertyException {
    return props.getString(ClientProperty.KEYSTORE_PASS).toCharArray();
  }

  public int getBufferSizeInMB() {
    return bufferSizeInMB;
  }

}
