package client;

import client.cache.ClientCacheController;
import client.crypt.ClientDHHelper;
import client.props.ClientProperty;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.stream.JsonReader;
import shared.errors.properties.PropertyException;
import shared.errors.request.InvalidFormatException;
import shared.parameters.ServerParameterMap;
import shared.parameters.ServerParameterType;
import shared.utils.GsonUtils;
import shared.utils.SafeInputStreamReader;
import shared.utils.crypto.*;
import shared.utils.properties.CustomProperties;

import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

final class ClientProperties {
  final B64Helper B64Helper;
  final RNDHelper RNDHelper;
  final Gson GSON;
  final ClientCacheController CACHE;

  final String KEYSTORE_LOC;

  AEAHelper AEAHelper;
  PublicKey PUB_KEY;
  ClientDHHelper DHHelper;
  KSHelper KSHelper;
  KSHelper TSHelper;

  // Comms
  private JsonReader input;
  private OutputStream output;

  private CustomProperties props;

  private String pubKeyName;
  private final String seaSpec;
  private final String macSpec;
  private final PublicKey serverPubKey;

  ClientProperties(CustomProperties props, KSHelper KSHelper, KSHelper TSHelper, SSLSocket socket) throws PropertyException, GeneralSecurityException, IOException {
    this.props = props;
    this.KSHelper = KSHelper;
    this.TSHelper = TSHelper;

    // Set socket input and output and get server public key
    input = new JsonReader(new SafeInputStreamReader(socket.getInputStream(), props.getInt(ClientProperty.BUFFER_SIZE_MB)));
    output = socket.getOutputStream();
    X509Certificate certificate = (X509Certificate) socket.getSession().getPeerCertificates()[0];
    serverPubKey = certificate.getPublicKey();

    B64Helper = new B64Helper();
    RNDHelper = new RNDHelper();
    GSON = GsonUtils.buildGsonInstance();

    // System props
    CACHE = new ClientCacheController(props.getInt(ClientProperty.CACHE_SIZE));

    // Crypt props
    seaSpec = props.getString(ClientProperty.SEA_SPEC);
    macSpec = props.getString(ClientProperty.MAC_SPEC);
    KEYSTORE_LOC = props.getString(ClientProperty.KEYSTORE_LOC);
  }

  // Initialize AEAHelper
  void initAEAHelper(ServerParameterMap serverParams) throws GeneralSecurityException, PropertyException {
    String pubKeyAlg = serverParams.getParameterValue(ServerParameterType.PUB_KEY_ALG);
    String certSignAlg = serverParams.getParameterValue(ServerParameterType.CERT_SIG_ALG);
    int pubKeySize = Integer.parseInt(serverParams.getParameterValue(ServerParameterType.CERT_SIG_ALG));

    AEAHelper = new AEAHelper(pubKeyAlg, certSignAlg, pubKeySize);

    // Get pub key and assign it
    pubKeyName = props.getString(ClientProperty.PUB_KEY_NAME);
    PUB_KEY = KSHelper.getCertificate(pubKeyName).getPublicKey();
  }

  // Initialize DHHelper
  void initDHHelper(ServerParameterMap serverParams) throws GeneralSecurityException {
    String dhAlg = serverParams.getParameterValue(ServerParameterType.DH_ALG);
    String dhP = serverParams.getParameterValue(ServerParameterType.DH_P);
    String dhG = serverParams.getParameterValue(ServerParameterType.DH_G);
    int dhKeySize = Integer.parseInt(serverParams.getParameterValue(ServerParameterType.DH_KEYSIZE));
    String dhHashAlg = serverParams.getParameterValue(ServerParameterType.DH_HASH_ALG);

    DHHelper = new ClientDHHelper(dhAlg, dhHashAlg, dhKeySize, dhP, dhG);
  }

  PrivateKey getPrivateKey() throws GeneralSecurityException {
    return (PrivateKey) KSHelper.getKey(pubKeyName);
  }

  public PublicKey getServerPublicKey() {
    return serverPubKey;
  }

  char[] keyStorePassword() throws PropertyException {
    return props.getString(ClientProperty.KEYSTORE_PASS).toCharArray();
  }

  public String getSeaSpec() {
    return seaSpec;
  }

  public String getMacSpec() {
    return macSpec;
  }

  public void sendRequest(JsonObject jsonObject) throws IOException {
    output.write(GSON.toJson(jsonObject).getBytes());
  }

  public JsonObject receiveRequest() throws InvalidFormatException {
    return GsonUtils.parseRequest(input);
  }
}
