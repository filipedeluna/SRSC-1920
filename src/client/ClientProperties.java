package client;

import client.cache.ClientCacheController;
import client.crypt.ClientDHHelper;
import client.errors.ClientException;
import client.props.ClientProperty;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import com.google.gson.stream.JsonReader;
import shared.errors.properties.PropertyException;
import shared.errors.request.InvalidFormatException;
import shared.http.HTTPStatus;
import shared.parameters.ServerParameterMap;
import shared.parameters.ServerParameterType;
import shared.response.ErrorResponse;
import shared.response.GsonResponse;
import shared.response.OkResponseWithNonce;
import shared.utils.GsonUtils;
import shared.utils.SafeInputStreamReader;
import shared.utils.crypto.*;
import shared.utils.properties.CustomProperties;

import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Type;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

final class ClientProperties {
  final B64Helper b64Helper;
  final RNDHelper rndHelper;
  final Gson GSON;
  final ClientCacheController cache;

  final String KEYSTORE_LOC;

  AEAHelper aeaHelper;
  PublicKey PUB_KEY;
  ClientDHHelper dhHelper;
  KSHelper ksHelper;
  KSHelper tshelper;

  // Comms
  private JsonReader input;
  private OutputStream output;

  private final CustomProperties props;
  private final HashHelper hashHelper;
  private final String seaSpec;
  private final String macSpec;
  private PublicKey serverPubKey;
  private final PublicKey clientPublicKey;

  private String pubKeyName;
  private ClientSession session;

  ClientProperties(CustomProperties props, KSHelper ksHelper, KSHelper tsHelper) throws PropertyException, GeneralSecurityException {
    this.props = props;
    this.ksHelper = ksHelper;
    this.tshelper = tsHelper;

    // Create hash helper for generating uuids
    hashHelper = new HashHelper(props.getString(ClientProperty.UUID_HASH));

    // Set socket input and output and get server public key
    b64Helper = new B64Helper();
    rndHelper = new RNDHelper();
    GSON = GsonUtils.buildGsonInstance();

    // System props
    cache = new ClientCacheController(props.getInt(ClientProperty.CACHE_SIZE));

    // Crypt props
    seaSpec = props.getString(ClientProperty.SEA_SPEC);
    macSpec = props.getString(ClientProperty.MAC_SPEC);
    KEYSTORE_LOC = props.getString(ClientProperty.KEYSTORE_LOC);
    clientPublicKey = ksHelper.getPublicKey(props.getString(ClientProperty.PUB_KEY_NAME));
  }

  // Initialize AEAHelper
  void initAEAHelper(ServerParameterMap serverParams) throws GeneralSecurityException, PropertyException {
    String pubKeyAlg = serverParams.getParameterValue(ServerParameterType.PUB_KEY_ALG);
    String certSignAlg = serverParams.getParameterValue(ServerParameterType.CERT_SIG_ALG);

    aeaHelper = new AEAHelper(pubKeyAlg, certSignAlg);

    // Get pub key and assign it
    pubKeyName = props.getString(ClientProperty.PUB_KEY_NAME);
    PUB_KEY = ksHelper.getCertificate(pubKeyName).getPublicKey();
  }

  // Initialize DHHelper
  void initDHHelper(ServerParameterMap serverParams) throws GeneralSecurityException {
    String dhAlg = serverParams.getParameterValue(ServerParameterType.DH_ALG);
    String dhP = serverParams.getParameterValue(ServerParameterType.DH_P);
    String dhG = serverParams.getParameterValue(ServerParameterType.DH_G);
    int dhKeySize = Integer.parseInt(serverParams.getParameterValue(ServerParameterType.DH_KEYSIZE));
    String dhHashAlg = serverParams.getParameterValue(ServerParameterType.DH_HASH_ALG);

    dhHelper = new ClientDHHelper(dhAlg, dhHashAlg, dhKeySize, dhP, dhG);
  }

  PrivateKey getPrivateKey() throws GeneralSecurityException {
    return (PrivateKey) ksHelper.getKey(pubKeyName);
  }

  public PublicKey getServerPublicKey() {
    return serverPubKey;
  }

  public PublicKey getClientPublicKey() throws KeyStoreException {
    return ksHelper.getPublicKey(pubKeyName);
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

  public String generateUUID(String username) {
    byte[] hash = hashHelper.hash(username.getBytes(), clientPublicKey.getEncoded());

    return b64Helper.encode(hash);
  }

  public void sendRequest(JsonObject jsonObject) throws IOException {
    output.write(GSON.toJson(jsonObject).getBytes());
  }

  public <T> T receiveRequest(Type type) throws ClientException {
    JsonObject jsonObject;
    GsonResponse response;

    // Check if retrieved object is a GsonResponse as expected
    try {
      jsonObject = GsonUtils.parseRequest(input);
      response = GSON.fromJson(jsonObject, GsonResponse.class);
    } catch (JsonSyntaxException | InvalidFormatException e) {
      throw new ClientException("Failed to parse response object. Probably corrupted");
    }

    // If there was an error (code != 200/OK), try to extract it
    if (response.getStatus().getCode() != HTTPStatus.OK.code()) {
      try {
        response = GSON.fromJson(jsonObject, ErrorResponse.class);
        throw new ClientException("Request Failed: " +
            response.getStatus().getCode() + " " +
            response.getStatus().getMessage() + " - " +
            ((ErrorResponse) response).getError()
        );
      } catch (JsonSyntaxException e) {
        throw new ClientException("Failed to parse error response object. Probably corrupted");
      }
    }

    // Return the request data as an OKResponse object
    try {
      return GSON.fromJson(jsonObject, type);
    } catch (JsonSyntaxException e) {
      throw new ClientException("Failed to parse response object. Probably corrupted");
    }
  }

  public <T> T receiveRequestWithNonce(JsonObject requestData, Type type) throws ClientException {
    try {
      T response = receiveRequest(type);

      if (!requestData.get("nonce").getAsString().equals(((OkResponseWithNonce) response).getNonce()))
        throw new ClientException("The nonce retrieved from the server does not match.");

      return (T) response;
    } catch (JsonSyntaxException e) {
      throw new ClientException("Response with nonce was expected but not received");
    }
  }

  public ClientSession getSession() {
    return session;
  }

  public void connect(SSLSocket socket) throws IOException, PropertyException {
    input = new JsonReader(new SafeInputStreamReader(socket.getInputStream(), this.props.getInt(ClientProperty.BUFFER_SIZE_MB)));
    output = socket.getOutputStream();

    X509Certificate certificate = (X509Certificate) socket.getSession().getPeerCertificates()[0];
    serverPubKey = certificate.getPublicKey();
  }

  public <T> T fromJson(JsonObject jsonObject, Type type) {
    return GSON.fromJson(jsonObject, type);
  }

  public void establishSession(ClientSession session) {
    this.session = session;
  }

  /*
    Utils
  */

}
