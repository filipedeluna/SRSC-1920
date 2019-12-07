package client;

import client.crypt.DHKeyType;
import client.errors.ClientException;
import client.props.ClientProperty;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.stream.JsonReader;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import shared.ServerRequest;
import shared.parameters.ServerParameterMap;
import server.db.wrapper.Message;
import server.db.wrapper.Receipt;
import server.db.wrapper.User;
import server.response.*;
import shared.errors.properties.PropertyException;
import shared.errors.request.InvalidFormatException;
import shared.utils.GsonUtils;
import shared.utils.SafeInputStreamReader;
import shared.utils.crypto.KSHelper;
import shared.utils.properties.CustomProperties;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.net.ssl.*;
import java.io.*;
import java.lang.reflect.Type;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

public class Client {
  private static final String PROPS_PATH = "src/client/props/client.properties";

  public static void main(String[] args) {
    System.setProperty("java.net.preferIPv4Stack", "true");
    Security.addProvider(new BouncyCastleJsseProvider());

    // Get properties from file
    CustomProperties properties = null;
    try {
      properties = new CustomProperties(PROPS_PATH);
    } catch (PropertyException e) {
      System.err.println(e.getMessage());
      System.exit(-1);
    }

    try {
      // Gets the client keystore
      KSHelper ksHelper = getKeyStore(properties);
      KSHelper tsHelper = getTrustStore(properties);

      // Create SSL Socket
      int serverPort = properties.getInt(ClientProperty.SERVER_PORT);
      String serverAddress = properties.getString(ClientProperty.SERVER_ADDRESS);
      SSLContext sslContext = buildSSLContext(ksHelper, tsHelper);
      SSLSocketFactory factory = sslContext.getSocketFactory();
      SSLSocket socket = (SSLSocket) factory.createSocket(serverAddress, serverPort);

      // Set enabled protocols and cipher suites and start SSL socket handshake with server
      String[] enabledProtocols = properties.getStringArr(ClientProperty.TLS_PROTOCOLS);
      String[] enabledCipherSuites = properties.getStringArr(ClientProperty.TLS_CIPHERSUITES);
      socket.setEnabledProtocols(enabledProtocols);
      socket.setEnabledCipherSuites(enabledCipherSuites);

      socket.startHandshake();

      // Create client properties
      ClientProperties cProps = new ClientProperties(properties, ksHelper, tsHelper, socket);

      // Request shared parameters
      JsonObject serverParamsJSON = requestParams(cProps);

      // Create DH and AEA helper from params
      ServerParameterMap serverParams = cProps.GSON.fromJson(serverParamsJSON.toString(), ServerParameterMap.class);
      cProps.initAEAHelper(serverParams);
      cProps.initDHHelper(serverParams);

      ServerRequest request = ServerRequest.fromString(args[0]);

      if (request == null) {
        System.err.print("Invalid option.");
        System.exit(-1);
      }

      // Initialize response object with request type
      JsonObject requestData = new JsonObject();
      requestData.addProperty("type", request.val());

      // Get nonce if supposed to for the requested route
      if (request.needsNonce())
        requestData.addProperty("nonce", cProps.RNDHelper.getString(16, true));

      switch (request) {
        case CREATE:
          createUser(cProps, requestData);
        case LIST:
          listUsers(cProps, requestData);
          break;
        case NEW:
          listNewMessages(cProps, requestData);
          break;
        case ALL:
          listAllMessages(cProps, requestData);
          break;
        case SEND:
          //missing message encryption
          sendMessages(cProps, requestData);
        case RECEIVE:
          // TODO missing message decryption
          //contem o receipt, receipt enviado dps de ler
          receiveMessages(cProps, requestData);
          break;
        case STATUS:
          status(cProps, requestData);
          break;
        case RECEIPT:
        default:
          // TODO Invalid command
          // TODO print available commands here
          // TODO Also create args[0] with help command at start
          System.err.println("Invalid route");
      }
    } catch (GeneralSecurityException e) {
      //not the same signature
    } catch (Exception e) {
      handleException(e, false);
    } finally {
      System.exit(-1);
    }
  }

  private static void createUser(ClientProperties cProps, JsonObject requestData) throws IOException, GeneralSecurityException, InvalidFormatException, ClientException {
    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));

    // TODO uuid é gerado a partir de hash de pubkey. ver enunciado
    String uuid = bf.readLine();
    requestData.addProperty("uuid", uuid);

    // TODO nome de utilizador podera ser algo como hash(username + pubkeybytes)
    // TODO permitindo assim diferentes usernames
    // Generate Parameter Spec and create dh keypairs for mac and sea
    DHParameterSpec dhSpec = new DHParameterSpec(cProps.DHHelper.getP(), cProps.DHHelper.getG());
    KeyPair dhSeaKeypair = cProps.DHHelper.genKeyPair(dhSpec);
    KeyPair dhMacKeypair = cProps.DHHelper.genKeyPair(dhSpec);

    // Check user keyps exist
    if (cProps.KSHelper.dhKeyPairExists(uuid, DHKeyType.SEA))
      throw new ClientException("User sea key already exists.");

    if (cProps.KSHelper.dhKeyPairExists(uuid, DHKeyType.MAC))
      throw new ClientException("User mac key already exists.");

    // Keys do not exist so save them to file
    cProps.KSHelper.saveDHKeyPair(uuid, DHKeyType.SEA, dhSeaKeypair);
    cProps.KSHelper.saveDHKeyPair(uuid, DHKeyType.MAC, dhSeaKeypair);

    // TODO sign all the security properties
    // Add all security properties to the header
    byte[] seaDHPubKeyBytes = dhSeaKeypair.getPublic().getEncoded();
    byte[] macDHPubKeyBytes = dhMacKeypair.getPublic().getEncoded();

    requestData.addProperty("seaDHValue", cProps.B64Helper.encode(seaDHPubKeyBytes));
    requestData.addProperty("macDHValue", cProps.B64Helper.encode(macDHPubKeyBytes));
    requestData.addProperty("seaSpec", cProps.getSeaSpec());
    requestData.addProperty("macSpec", cProps.getMacSpec());

    // Get byte array of all properties and sign them
    byte[] paramsSignatureBytes = cProps.AEAHelper.sign(cProps.getPrivateKey(),
        seaDHPubKeyBytes,
        macDHPubKeyBytes,
        cProps.getSeaSpec().getBytes(),
        cProps.getMacSpec().getBytes()
    );

    // Add encoded signature to request and send request with JSON data
    requestData.addProperty("secDataSignature", cProps.B64Helper.encode(paramsSignatureBytes));
    cProps.sendRequest(requestData);

    JsonObject obj = cProps.receiveRequest();
    CreateUserResponse resp = cProps.GSON.fromJson(obj, CreateUserResponse.class);

    System.out.println("User_ID: " + resp.getUserId());
  }

  private static User listUsers(ClientProperties cProps, JsonObject requestData) throws IOException, InvalidFormatException {
    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));
    int userid = 0;
    boolean u = true;
    try {
      userid = Integer.parseInt(bf.readLine());
      requestData.addProperty("userId", userid);
    } catch (IOException e) {
      u = false;
    }
    cProps.sendRequest(requestData);

    //response
    JsonObject jsonObject = cProps.receiveRequest();
    ListUsersResponse lur = cProps.GSON.fromJson(jsonObject, ListUsersResponse.class);

    ArrayList<User> l = cProps.GSON.fromJson(lur.getUsers(), (Type) new ArrayList<User>() {
    }.getClass());
    if (u) {
      System.out.println("Listing user :" + userid);
      System.out.println(l.get(0).getUuid());
      return l.get(0);
    } else {
      System.out.println("Listing users");
      for (User user : l) {
        System.out.printf("User id : %s \t User uuid : %s\n", user.getId(), user.getUuid());
      }

    }
    return null;
  }

  private static void listNewMessages(ClientProperties cProps, JsonObject requestData) throws IOException, InvalidFormatException {
    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));

    int userid = Integer.parseInt(bf.readLine());
    requestData.addProperty("userId", userid);
    cProps.sendRequest(requestData);


    JsonObject obj = cProps.receiveRequest();

    ListNewMessagesResponse lmr = cProps.GSON.fromJson(obj, ListNewMessagesResponse.class);
    System.out.println("New messages:");
    for (int s : lmr.getNewMessageIds()) {
      System.out.println("Message id: " + s);
    }
  }

  private static void listAllMessages(ClientProperties cProps, JsonObject requestData) throws IOException, InvalidFormatException {
    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));

    int userid = Integer.parseInt(bf.readLine());
    requestData.addProperty("userId", userid);
    cProps.sendRequest(requestData);

    JsonObject jsonObject = cProps.receiveRequest();
    ListMessagesResponse lmr = cProps.GSON.fromJson(jsonObject, ListMessagesResponse.class);

    System.out.println("Received:");
    for (String s : lmr.getReceivedMessageIds()) {
      System.out.println("Message id: " + s);
    }
    System.out.println("Sent:");
    for (int s : lmr.getSentMessageIds()) {
      System.out.println("Message id: " + s);
    }
  }

  private static void sendMessages(ClientProperties cProps, JsonObject requestData) throws IOException, InvalidFormatException, GeneralSecurityException, PropertyException {
    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));

    int clientId = Integer.parseInt(bf.readLine());
    requestData.addProperty("source", clientId);

    int destinationId = Integer.parseInt(bf.readLine());
    requestData.addProperty("destination", destinationId);

    String text = bf.readLine();

    // TODO Create and save dh shared sea and mac keys
    //if (!cProps.KSHelper.dhKeyPairExists(clientId, destinationId)) {
    //  cProps.KSHelper.saveDHKeyPair(clientId, destinationId, socket);
   // }

    //load shared key
    cProps.KSHelper.getKey(clientId + "-" + destinationId + "-shared");

  }

  private static void receiveMessages(ClientProperties cProps, JsonObject requestData) throws IOException, InvalidFormatException {
    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));
    int messageid = Integer.parseInt(bf.readLine());
    requestData.addProperty("userId", messageid);
    cProps.sendRequest(requestData);

    JsonObject obj = cProps.receiveRequest();
    ReceiveMessageResponse lmr = cProps.GSON.fromJson(obj, ReceiveMessageResponse.class);
    Message m = lmr.getMessage();

    //substituido depois pela chave publica para verificar assinatura
    String integrity = m.getSenderSignature();
    String text = m.getText();
    int sentFrom = m.getSenderId();
    int mid = m.getId();

    //verificacao de assinatura

    //mostrar ao utilizador a mensagem
    System.out.printf("Message sent from %d with ID %d\n", sentFrom, mid);
    System.out.println(text);

    //SEND RECEIPT WITH CONTENT SIGNATURE
  }

  private static void status(ClientProperties cProps, JsonObject requestData) throws IOException, InvalidFormatException {
    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));

    int messageid = Integer.parseInt(bf.readLine());
    requestData.addProperty("userId", messageid);
    cProps.sendRequest(requestData);

    JsonObject obj = cProps.receiveRequest();

    MessageReceiptsResponse lmr = cProps.GSON.fromJson(obj, MessageReceiptsResponse.class);
    System.out.println("Showing status for message: " + lmr.getMessage().getId());
    for (Receipt r : lmr.getReceipts()) {
      System.out.println("Date: " + r.getDate());
      System.out.println("Signature: " + r.getReceiverSignature());
    }

  }

  private static JsonObject requestParams(ClientProperties cProps) throws InvalidFormatException, GeneralSecurityException, IOException {
    JsonObject requestData = new JsonObject();
    //vai explodir no server devido a nao ter o decode b64
    requestData.addProperty("type", "params");
    requestData.addProperty("nonce", cProps.RNDHelper.getString(16, true));
    cProps.sendRequest(requestData);

    //parses answer from server
    JsonObject obj = cProps.receiveRequest();
    ParametersResponse response = cProps.GSON.fromJson(obj.toString(), ParametersResponse.class);

    cProps.AEAHelper.verifySignature(cProps.getServerPublicKey(), response.getParameters().getBytes(), response.getSignature().getBytes());
    //gets the json
    return cProps.GSON.fromJson(response.getParameters(), JsonObject.class);
  }

  private static void getUsers(KeyStore keyStore, int sourceId, int destinationId, SSLSocket socket, ClientProperties cProps) throws IOException, InvalidFormatException, GeneralSecurityException, PropertyException {
    JsonObject requestData = new JsonObject();
    requestData.addProperty("type", "dhvaluereq");
    requestData.addProperty("nonce", cProps.RNDHelper.getString(16, true));
    requestData.addProperty("destiny_uuid", destinationId);

    socket.getOutputStream().write(cProps.GSON.toJson(requestData).getBytes());

    JsonObject jsonObject = cProps.receiveRequest();
    RequestDestinyDHvalue req = cProps.GSON.fromJson(jsonObject, RequestDestinyDHvalue.class);
    X509Certificate certificate = (X509Certificate) socket.getSession().getPeerCertificates()[0];
    //validar assinatura
    PublicKey publicKeyserv = certificate.getPublicKey();
    cProps.AEAHelper.verifySignature(publicKeyserv, req.getDhdentinyvalue().getBytes(), req.getSecdata().getBytes());

    KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");
    PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(req.getDhdentinyvalue().getBytes()));

    //generate shared key between src - dst
    KeyAgreement keyAgree = KeyAgreement.getInstance("DiffieHellman");
    PrivateKey pk = (PrivateKey) keyStore.getKey(sourceId + "-priv", cProps.keyStorePassword());
    keyAgree.init(pk);
    keyAgree.doPhase(publicKey, true);
    byte[] sharedKeyBytes = keyAgree.generateSecret();

    //gravar na keystore
    PrivateKey shared = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(sharedKeyBytes));
    KeyStore.SecretKeyEntry sharedkeyentry = new KeyStore.SecretKeyEntry((SecretKey) shared);
    KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(cProps.keyStorePassword());
    keyStore.setEntry(sourceId + "-" + destinationId + "-shared", sharedkeyentry, protectionParam);
    keyStore.store(new FileOutputStream(new File(cProps.KEYSTORE_LOC)), cProps.keyStorePassword());

    // TODO save pair in keystore
    //  cProps.KSHelper.save(sourceId + "-" + destinationId + "-shared", );

  }

  private static void handleException(Exception e, boolean debugMode) {
    boolean expected = false;

    if (e instanceof PropertyException)
      expected = true;

    if (expected) {
      System.err.println(e.getMessage());
    } else {
      System.err.println("CRITICAL ERROR.");
    }

    if (debugMode)
      e.printStackTrace();
  }

  private static KSHelper getKeyStore(CustomProperties properties) throws PropertyException, GeneralSecurityException, IOException {
    String keyStoreLoc = properties.getString(ClientProperty.KEYSTORE_LOC);
    String keyStorePass = properties.getString(ClientProperty.KEYSTORE_PASS);
    String keyStoreType = properties.getString(ClientProperty.KEYSTORE_TYPE);

    return new KSHelper(keyStoreLoc, keyStoreType, keyStorePass.toCharArray(), false);
  }

  private static KSHelper getTrustStore(CustomProperties properties) throws PropertyException, IOException, GeneralSecurityException {
    String trustStoreLoc = properties.getString(ClientProperty.TRUSTSTORE_LOC);
    String trustStorePass = properties.getString(ClientProperty.TRUSTSTORE_PASS);
    String trustStoreType = properties.getString(ClientProperty.TRUSTSTORE_TYPE);

    return new KSHelper(trustStoreLoc, trustStoreType, trustStorePass.toCharArray(), true);
  }

  private static SSLContext buildSSLContext(KSHelper keyStore, KSHelper trustStore) throws GeneralSecurityException {
    KeyManagerFactory keyManagerFactory = keyStore.getKeyManagerFactory();
    TrustManagerFactory trustManagerFactory = trustStore.getTrustManagerFactory();
    KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
    TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

    SSLContext sslContext = SSLContext.getInstance("TLS", "BC");
    sslContext.init(keyManagers, trustManagers, new SecureRandom());

    return sslContext;
  }

  /*
    UTILS
  */

  private static String getCurrentDate() {
    DateFormat df = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");

    return df.format(new Date());
  }
}
