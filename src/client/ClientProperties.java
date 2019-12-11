package client;

import client.cache.ClientCacheController;
import client.cache.UserCacheEntry;
import client.crypt.ClientDHHelper;
import client.errors.ClientException;
import client.props.ClientProperty;
import client.utils.FileHelper;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import com.google.gson.stream.JsonReader;
import shared.Pair;
import shared.errors.properties.PropertyException;
import shared.errors.request.InvalidFormatException;
import shared.http.HTTPStatus;
import shared.parameters.ServerParameterMap;
import shared.parameters.ServerParameter;
import shared.response.ErrorResponse;
import shared.response.GsonResponse;
import shared.response.OkResponseWithNonce;
import shared.utils.GsonUtils;
import shared.utils.SafeInputStreamReader;
import shared.utils.crypto.*;
import shared.utils.crypto.util.DHKeyType;
import shared.utils.properties.CustomProperties;

import javax.crypto.*;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Type;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

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
  FileHelper fileHelper;

  // Comms
  private JsonReader input;
  private OutputStream output;

  private final CustomProperties props;
  private final HashHelper uuidHashHelper;
  private final String seaSpec;
  private final String macSpec;
  private PublicKey serverPubKey;
  private final PublicKey clientPublicKey;

  private String pubKeyName;
  ClientSession session;

  // SSL params
  private SSLSocketFactory sslSocketFactory;
  public int serverPort;
  public String serverAddress;
  public String[] tlsProtocols;
  public String[] tlsCiphersuites;
  public SSLSocket sslSocket;
  public int bufferSize;

  // Server params
  private String dhAlg;
  private String dhHashAlg;
  private BigInteger dhP;
  private BigInteger dhG;
  private int dhKeySize;

  private String pubKeyAlg;
  private String certSignAlg;

  ClientProperties(CustomProperties props, KSHelper ksHelper, KSHelper tsHelper, SSLSocketFactory sslSocketFactory) throws PropertyException, GeneralSecurityException, IOException {
    this.props = props;
    this.ksHelper = ksHelper;
    this.tshelper = tsHelper;

    // Load SSL params
    this.sslSocketFactory = sslSocketFactory;
    serverPort = props.getInt(ClientProperty.SERVER_PORT);
    serverAddress = props.getString(ClientProperty.SERVER_ADDRESS);
    tlsProtocols = props.getStringArr(ClientProperty.TLS_PROTOCOLS);
    tlsCiphersuites = props.getStringArr(ClientProperty.TLS_CIPHERSUITES);
    bufferSize = props.getInt(ClientProperty.BUFFER_SIZE_MB);

    // Get public key and cert
    pubKeyName = props.getString(ClientProperty.PUB_KEY_NAME);
    PUB_KEY = ksHelper.getCertificate(pubKeyName).getPublicKey();

    // Set up file helper
    fileHelper = new FileHelper(props.getString(ClientProperty.OUTPUT_FOLDER));

    // Create hash helper for generating uuids
    uuidHashHelper = new HashHelper(props.getString(ClientProperty.UUID_HASH));

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
    byte[] hash = uuidHashHelper.hash(username.getBytes(), clientPublicKey.getEncoded());

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

  public <T> T fromJson(JsonObject jsonObject, Type type) {
    return GSON.fromJson(jsonObject, type);
  }

  public void establishSession(ClientSession session) {
    this.session = session;
  }

  public Key loadSharedKey(int clientId, int destinationId, DHKeyType type) throws PropertyException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
    return ksHelper.getSharedKey(clientId, destinationId, type, keyStorePassword());
  }

  public void closeConnection() throws IOException {
    input.close();
    output.close();
    sslSocket.close();
    sslSocket = null;
  }

  public void startConnection() throws IOException {
    // check if previous connection was still on
    if (sslSocket != null) {
      input.close();
      output.close();
      sslSocket.close();
    }

    // Create socket
    sslSocket = (SSLSocket) sslSocketFactory.createSocket(serverAddress, serverPort);
    sslSocket.setSoTimeout(10 * 1000); // 10 seconds

    // Set enabled protocols and cipher suites and start SSL socket handshake with server
    sslSocket.setEnabledProtocols(tlsProtocols);
    sslSocket.setEnabledCipherSuites(tlsCiphersuites);

    // Start handshake and register input and output
    sslSocket.startHandshake();

    input = new JsonReader(new SafeInputStreamReader(sslSocket.getInputStream(), bufferSize));
    output = sslSocket.getOutputStream();

    // Get server public key
    X509Certificate certificate = (X509Certificate) sslSocket.getSession().getPeerCertificates()[0];
    serverPubKey = certificate.getPublicKey();
  }

  void loadServerParams(ServerParameterMap map) throws GeneralSecurityException {

    // Load all the parameters and assign them
    dhAlg = map.getParameter(ServerParameter.DH_ALG);
    dhHashAlg = map.getParameter(ServerParameter.DH_HASH_ALG);
    dhP = new BigInteger(map.getParameter(ServerParameter.DH_P));
    dhG = new BigInteger(map.getParameter(ServerParameter.DH_G));
    dhKeySize = Integer.parseInt(map.getParameter(ServerParameter.DH_KEYSIZE));

    pubKeyAlg = map.getParameter(ServerParameter.PUB_KEY_ALG);
    certSignAlg = map.getParameter(ServerParameter.CERT_SIG_ALG);

    // Create helpers from received params
    aeaHelper = new AEAHelper(pubKeyAlg, certSignAlg);
    dhHelper = new ClientDHHelper(dhAlg, dhHashAlg, dhKeySize, dhP, dhG);
  }

  Pair<Key, Key> getSharedKeys(int destinationId) throws PropertyException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, InvalidKeySpecException, IllegalBlockSizeException, ClassNotFoundException {
    // Get shared keys
    Key sharedSeaKey = ksHelper.getSharedKey(session.getId(), destinationId, DHKeyType.SEA, keyStorePassword());
    Key sharedMacKey = ksHelper.getSharedKey(session.getId(), destinationId, DHKeyType.MAC, keyStorePassword());

    // If shared keys don't exist, generate them
    if (sharedSeaKey == null || sharedMacKey == null) {
      generateDHSharedKeys(destinationId);

      // Get them again
      sharedSeaKey = ksHelper.getSharedKey(session.getId(), destinationId, DHKeyType.SEA, keyStorePassword());
      sharedMacKey = ksHelper.getSharedKey(session.getId(), destinationId, DHKeyType.MAC, keyStorePassword());
    }

    return new Pair<>(sharedSeaKey, sharedMacKey);
  }

  /*
    Utils
  */

  // TODO Catch some easy to understand exceptions all around... throwing 300 types isnt good
  private void generateDHSharedKeys(int destinationId) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, KeyStoreException, IOException, CertificateException, IllegalBlockSizeException, ClassNotFoundException, InvalidAlgorithmParameterException, BadPaddingException, PropertyException {
    // Get destination user's public keys
    UserCacheEntry destinationUser = cache.getUser(destinationId);
    PublicKey destinationDHPubSeaKey = dhHelper.generatePublicKey(new X509EncodedKeySpec(destinationUser.getDhSeaPubKey()));
    PublicKey destinationDHPubMacKey = dhHelper.generatePublicKey(new X509EncodedKeySpec(destinationUser.getDhMacPubKey()));

    // Get sessions private keys and generate the shared dh key
    PrivateKey sessionPrivSeaDHKey = ksHelper.loadDHKeyPair(session.getUUID(), DHKeyType.SEA).getPrivate();
    PrivateKey sessionPrivMacDHKey = ksHelper.loadDHKeyPair(session.getUUID(), DHKeyType.MAC).getPrivate();

    int seaKeySize = session.seaHelper.getMaxKeySize();
    int macKeySize = session.macHelper.getMaxKeySize();

    byte[] sharedSeaKey = dhHelper.genSharedKey(sessionPrivSeaDHKey, destinationDHPubSeaKey, seaKeySize);
    byte[] sharedMacKey = dhHelper.genSharedKey(sessionPrivMacDHKey, destinationDHPubMacKey, macKeySize);

    // Generate secret keys from bytes
    SecretKey sharedSeaKeySpec = session.seaHelper.getKeyFromBytes(sharedSeaKey);
    SecretKey sharedMacKeySpec = session.macHelper.getKeyFromBytes(sharedMacKey);

    // Save the generated keys
    ksHelper.saveSharedKey(session.getId(), destinationId, DHKeyType.SEA, sharedSeaKeySpec, keyStorePassword());
    ksHelper.saveSharedKey(session.getId(), destinationId, DHKeyType.MAC, sharedMacKeySpec, keyStorePassword());
  }
}
