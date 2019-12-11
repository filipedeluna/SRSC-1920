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
  private final Gson GSON;
  final ClientCacheController cache;

  private final String KEYSTORE_LOC;

  AEAHelper aeaHelper;
  ClientDHHelper dhHelper;
  final KSHelper ksHelper;
  private final KSHelper tshelper;
  FileHelper fileHelper;

  // Comms
  private JsonReader input;
  private OutputStream output;

  private final CustomProperties props;
  private final HashHelper uuidHashHelper;
  private final String seaSpec;
  private final String macSpec;
  private PublicKey serverPubKey;
  private PublicKey clientPublicKey;
  private String clientPublicKeyName;

  ClientSession session;

  // SSL params
  private final SSLSocketFactory sslSocketFactory;
  private int serverPort;
  private String serverAddress;
  private String[] tlsProtocols;
  private String[] tlsCiphersuites;
  private SSLSocket sslSocket;
  private int bufferSize;

  // PKI
  private final String pkiAddress;
  private final int pkiPort;

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

    // Can't get a public key if we haven't generated one yet
    if (props.getBool(ClientProperty.USE_PKI)) {
      clientPublicKeyName = props.getString(ClientProperty.PUB_KEY_NAME);
      clientPublicKey = ksHelper.getPublicKey(props.getString(ClientProperty.PUB_KEY_NAME));
    }
    // Load PKI params
    pkiAddress = props.getString(ClientProperty.PKI_ADDRESS);
    pkiPort = props.getInt(ClientProperty.PKI_PORT);
  }

  PrivateKey getPrivateKey() throws GeneralSecurityException {
    return (PrivateKey) ksHelper.getKey(clientPublicKeyName);
  }

  PublicKey getServerPublicKey() {
    return serverPubKey;
  }

  PublicKey getClientPublicKey() throws KeyStoreException {
    return ksHelper.getPublicKey(clientPublicKeyName);
  }

  private char[] keyStorePassword() throws PropertyException {
    return props.getString(ClientProperty.KEYSTORE_PASS).toCharArray();
  }

  String getSeaSpec() {
    return seaSpec;
  }

  String getMacSpec() {
    return macSpec;
  }

  String generateUUID(String username) {
    byte[] hash = uuidHashHelper.hash(username.getBytes(), clientPublicKey.getEncoded());

    return b64Helper.encode(hash);
  }

  void sendRequest(JsonObject jsonObject) throws IOException {
    output.write(GSON.toJson(jsonObject).getBytes());
  }

  <T> T receiveRequest(Type type) throws ClientException {
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

  <T> T receiveRequestWithNonce(JsonObject requestData, Type type) throws ClientException {
    try {
      T response = receiveRequest(type);

      if (!requestData.get("nonce").getAsString().equals(((OkResponseWithNonce) response).getNonce()))
        throw new ClientException("The nonce retrieved from the server does not match.");

      return response;
    } catch (JsonSyntaxException e) {
      throw new ClientException("Response with nonce was expected but not received");
    }
  }

  public <T> T fromJson(JsonObject jsonObject, Type type) {
    return GSON.fromJson(jsonObject, type);
  }

  void establishSession(ClientSession session) {
    this.session = session;
  }

  void closeConnection() throws IOException {
    input.close();
    output.close();
    sslSocket.close();
    sslSocket = null;
  }

  void startConnection() throws IOException {
    startConnection(false);
  }

  void startConnection(boolean pki) throws IOException {
    // check if previous connection was still on
    if (sslSocket != null) {
      input.close();
      output.close();
      sslSocket.close();
    }

    // Create socket
    if (pki)
      sslSocket = (SSLSocket) sslSocketFactory.createSocket(pkiAddress, pkiPort);
    else
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
    // Server params
    String dhAlg = map.getParameter(ServerParameter.DH_ALG);
    String dhHashAlg = map.getParameter(ServerParameter.DH_HASH_ALG);
    BigInteger dhP = new BigInteger(map.getParameter(ServerParameter.DH_P));
    BigInteger dhG = new BigInteger(map.getParameter(ServerParameter.DH_G));
    int dhKeySize = Integer.parseInt(map.getParameter(ServerParameter.DH_KEYSIZE));

    String pubKeyAlg = map.getParameter(ServerParameter.PUB_KEY_ALG);
    String certSignAlg = map.getParameter(ServerParameter.CERT_SIG_ALG);

    // Create helpers from received params
    aeaHelper = new AEAHelper(pubKeyAlg, certSignAlg);
    dhHelper = new ClientDHHelper(dhAlg, dhHashAlg, dhKeySize, dhP, dhG);
  }

  Pair<Key, Key> getSharedKeys(int destinationId) throws PropertyException, NoSuchAlgorithmException, ClientException {
    // Get shared keys
    try {
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
    } catch (UnrecoverableKeyException | KeyStoreException e) {
      throw new ClientException("Failed to get shared keys from keystore");
    }
  }

  /*
    Utils
  */
  private void generateDHSharedKeys(int destinationId) throws PropertyException, ClientException {
    UserCacheEntry destinationUser = cache.getUser(destinationId);

    // Get destination user's public keys
    PublicKey destinationDHPubSeaKey;
    PublicKey destinationDHPubMacKey;
    try {
      destinationDHPubSeaKey = dhHelper.generatePublicKey(new X509EncodedKeySpec(destinationUser.getDhSeaPubKey()));
      destinationDHPubMacKey = dhHelper.generatePublicKey(new X509EncodedKeySpec(destinationUser.getDhMacPubKey()));
    } catch (InvalidKeySpecException e) {
      throw new ClientException("Destination user's public keys are corrupted.");
    }

    // Get sessions private keys and generate the shared dh key
    PrivateKey sessionPrivSeaDHKey;
    PrivateKey sessionPrivMacDHKey;
    try {
      sessionPrivSeaDHKey = ksHelper.loadDHKeyPair(session.getUUID(), DHKeyType.SEA).getPrivate();
      sessionPrivMacDHKey = ksHelper.loadDHKeyPair(session.getUUID(), DHKeyType.MAC).getPrivate();
    } catch (ClassNotFoundException e) {
      throw new ClientException("Failed to read dh key data from file.");
    } catch (IllegalBlockSizeException | InvalidAlgorithmParameterException | BadPaddingException | IOException | InvalidKeyException e) {
      throw new ClientException("DH key file is corrupted.");
    }

    // Calculate max key size, but limiting to 512bits
    int seaKeySize;
    int macKeySize;
    try {
      seaKeySize = Math.min(session.seaHelper.getMaxKeySize(), 64);
      macKeySize = Math.min(session.macHelper.getMaxKeySize(), 64);
    } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
      throw new ClientException("User shared key algorithms are invalid.");
    }

    // Generate the shared keys by phasing dh keys
    byte[] sharedSeaKey;
    byte[] sharedMacKey;
    try {
      sharedSeaKey = dhHelper.genSharedKey(sessionPrivSeaDHKey, destinationDHPubSeaKey, seaKeySize);
      sharedMacKey = dhHelper.genSharedKey(sessionPrivMacDHKey, destinationDHPubMacKey, macKeySize);
    } catch (InvalidKeyException e) {
      throw new ClientException("Failed to generate shared keys.");
    }

    // Generate secret keys from bytes
    SecretKey sharedSeaKeySpec = session.seaHelper.getKeyFromBytes(sharedSeaKey);
    SecretKey sharedMacKeySpec = session.macHelper.getKeyFromBytes(sharedMacKey);

    // Save the generated keys
    try {
      ksHelper.saveSharedKey(session.getId(), destinationId, DHKeyType.SEA, sharedSeaKeySpec, keyStorePassword());
      ksHelper.saveSharedKey(session.getId(), destinationId, DHKeyType.MAC, sharedMacKeySpec, keyStorePassword());
    } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
      throw new ClientException("Failed to save generated shared keys.");
    }
  }
}
