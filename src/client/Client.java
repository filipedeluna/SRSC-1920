package client;

import client.crypt.DHKeyType;
import client.errors.ClientException;
import client.props.ClientProperty;
import client.utils.ClientRequest;
import com.google.gson.JsonObject;
import shared.errors.request.RequestException;
import shared.parameters.ServerParameterMap;
import shared.utils.CryptUtil;
import shared.wrappers.Message;
import shared.wrappers.Receipt;
import shared.wrappers.User;
import shared.errors.properties.PropertyException;
import shared.errors.request.InvalidFormatException;
import shared.parameters.ServerParameterType;
import shared.response.server.*;
import shared.utils.crypto.KSHelper;
import shared.utils.properties.CustomProperties;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.DHParameterSpec;
import javax.net.ssl.*;
import java.io.*;
import java.lang.reflect.Type;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

public class Client {
  private static final String PROPS_PATH = "src/client/props/client.properties";
  private static final boolean DEBUG_MODE = true;

  public static void main(String[] args) {
    System.setProperty("javax.net.debug", DEBUG_MODE ? "true" : "false");
    System.setProperty("java.net.preferIPv4Stack", "true");

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
      socket.setSoTimeout(10 * 1000); // 10 seconds

      // Set enabled protocols and cipher suites and start SSL socket handshake with server
      String[] enabledProtocols = properties.getStringArr(ClientProperty.TLS_PROTOCOLS);
      String[] enabledCipherSuites = properties.getStringArr(ClientProperty.TLS_CIPHERSUITES);
      socket.setEnabledProtocols(enabledProtocols);
      socket.setEnabledCipherSuites(enabledCipherSuites);

      // Start handshake
      System.out.println("SSL setup finished.");
      socket.startHandshake();
      System.out.println("Handshake completed.");

      // Create client properties
      ClientProperties cProps = new ClientProperties(properties, ksHelper, tsHelper, socket);

      // Request shared parameters and that initialize dh and aea helpers
      requestParams(cProps);

      while (true) {
        try {
          // Parse and validate request and create resquest object
          ClientRequest request = ClientRequest.fromString(args[0]);
          JsonObject requestData = new JsonObject();

          // Check request is valid and argument length correct
          if (request == null)
            throw new ClientException("Invalid command.");

          if (args.length != request.numberOfArgs() + 1)
            throw new ClientException("Invalid arguments.");

          // Initialize request object with request type
          requestData.addProperty("type", request.val());

          // Get nonce if supposed to for the requested route
          if (request.needsNonce())
            requestData.addProperty("nonce", cProps.rndHelper.getNonce());

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
            case LOGIN:
              login(cProps, requestData, args);
              break;
            case HELP:
              printCommands();
              break;
            case EXIT:
              System.out.println("Exited the client.");
              break;
            default:
              // TODO Invalid command
              // TODO print available commands here
              // TODO Also create args[0] with help command at start
              System.err.println("Invalid route");
          }
        } catch (ClientException e) {
          System.err.println(e.getMessage());
        }
      }
    } catch (Exception e) {
      System.err.println("CRITICAL ERROR: " + e.getMessage());
      System.exit(-1);
    }
  }

  private static void login(ClientProperties cProps, JsonObject requestData, String[] args) throws ClientException, IOException, InvalidFormatException {
    // Get username, compute uuid and add to request
    String username = args[1].trim();
    String uuid = cProps.generateUUID(username);

    requestData.addProperty("uuid", uuid);

    // Get response and check nonce
    JsonObject responseJsonObj = cProps.receiveRequest();
    LoginResponse resp = cProps.GSON.fromJson(responseJsonObj, LoginResponse.class);

    checkNonce(requestData, resp.getNonce());

    // Get user details from response and check data signature
    User user = resp.getUser();
    verifyUserSecDataSignature(user, cProps);

    // Check if user dh keys exist
    if (!cProps.ksHelper.dhKeyPairExists(username, DHKeyType.SEA) || !cProps.ksHelper.dhKeyPairExists(username, DHKeyType.SEA))
      throw new ClientException("User keys not found.");

    // Get user dh keys
    KeyPair seaDhKeyPair;
    KeyPair macDhKeyPair;
    try {
      seaDhKeyPair = cProps.ksHelper.loadDHKeyPair(username, DHKeyType.SEA);
      macDhKeyPair = cProps.ksHelper.loadDHKeyPair(username, DHKeyType.MAC);
    } catch (Exception e) {
      throw new ClientException("User keys are corrupted.");
    }

    // Create session and establish it
    ClientSession session = new ClientSession(
        user.getId(),
        user.getSeaSpec(),
        user.getMacSpec(),
        seaDhKeyPair,
        macDhKeyPair
    );

    cProps.establishSession(session);

    System.out.println("User " + username + " successfully logged in.");
  }

  // TODO OOOOOOOOOOOOOOOOO VERIFY THE NONCES EVERYWHERE

  private static ServerParameterMap requestParams(ClientProperties cProps) throws InvalidFormatException, GeneralSecurityException, IOException, ClientException {
    JsonObject requestData = new JsonObject();

    // Create request parameters and send request
    requestData.addProperty("type", "params");
    String nonce = cProps.rndHelper.getNonce();
    requestData.addProperty("nonce", nonce);
    cProps.sendRequest(requestData);

    // Get response and check nonce
    JsonObject responseJsonObj = cProps.receiveRequest();
    ParametersResponse paramsResponse = cProps.GSON.fromJson(responseJsonObj, ParametersResponse.class);
    checkNonce(nonce, paramsResponse.getNonce());

    // Create parameters map class from received JSON
    ServerParameterMap paramsMap = paramsResponse.getParameters();

    // Initialize AEA and DH Helper with the server parameters
    try {
      cProps.initAEAHelper(paramsMap);
      cProps.initDHHelper(paramsMap);
    } catch (Exception e) {
      throw new ClientException("The server parameters received are corrupted.");
    }

    // Verify parameters signature
    byte[] signatureDecoded = cProps.b64Helper.decode(paramsMap.getParameterValue(ServerParameterType.PARAM_SIG));
    byte[] paramsBytes = paramsMap.getAllParametersBytes();

    boolean sigValid = cProps.aeaHelper.verifySignature(cProps.getServerPublicKey(), paramsBytes, signatureDecoded);

    if (!sigValid)
      throw new ClientException("The server parameters signature is not valid.");

    return paramsMap;
  }

  private static void createUser(ClientProperties cProps, JsonObject requestData) throws IOException, GeneralSecurityException, RequestException, ClientException {
    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));

    // Generate a uuid from a users chosen username, adding entropy to it
    System.out.println("Insert desired username:");
    String username = bf.readLine().trim();
    String uuid = cProps.generateUUID(username);

    requestData.addProperty("uuid", uuid);

    // Generate Parameter Spec and create dh keypairs for mac and sea
    DHParameterSpec dhSpec = new DHParameterSpec(cProps.dhHelper.getP(), cProps.dhHelper.getG());
    KeyPair dhSeaKeypair = cProps.dhHelper.genKeyPair(dhSpec);
    KeyPair dhMacKeypair = cProps.dhHelper.genKeyPair(dhSpec);

    // Check user keys exist
    if (cProps.ksHelper.dhKeyPairExists(username, DHKeyType.SEA))
      throw new ClientException("User sea key already exists.");

    if (cProps.ksHelper.dhKeyPairExists(username, DHKeyType.MAC))
      throw new ClientException("User mac key already exists.");

    // Keys do not exist so save them to file
    cProps.ksHelper.saveDHKeyPair(username, DHKeyType.SEA, dhSeaKeypair);
    cProps.ksHelper.saveDHKeyPair(username, DHKeyType.MAC, dhSeaKeypair);

    // Add all security properties to the header
    byte[] seaDHPubKeyBytes = dhSeaKeypair.getPublic().getEncoded();
    byte[] macDHPubKeyBytes = dhMacKeypair.getPublic().getEncoded();

    requestData.addProperty("dhSeaPubKey", cProps.b64Helper.encode(seaDHPubKeyBytes));
    requestData.addProperty("dhMacPubKey", cProps.b64Helper.encode(macDHPubKeyBytes));
    requestData.addProperty("seaSpec", cProps.getSeaSpec());
    requestData.addProperty("macSpec", cProps.getMacSpec());

    // Get byte array of all properties and sign them
    byte[] paramsSignatureBytes = cProps.aeaHelper.sign(cProps.getPrivateKey(),
        seaDHPubKeyBytes,
        macDHPubKeyBytes,
        cProps.getSeaSpec().getBytes(),
        cProps.getMacSpec().getBytes()
    );

    // Add encoded signature to request and send request with JSON data
    requestData.addProperty("secDataSignature", cProps.b64Helper.encode(paramsSignatureBytes));
    cProps.sendRequest(requestData);

    // Get response and check nonce
    JsonObject responseJsonObj = cProps.receiveRequest();
    CreateUserResponse resp = cProps.GSON.fromJson(responseJsonObj, CreateUserResponse.class);

    checkNonce(requestData, resp.getNonce());

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
    cProps.ksHelper.getKey(clientId + "-" + destinationId + "-shared");

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

/*
  private static void getUsers(KeyStore keyStore, int sourceId, int destinationId, SSLSocket socket, ClientProperties cProps) throws IOException, InvalidFormatException, GeneralSecurityException, PropertyException {
    JsonObject requestData = new JsonObject();
    requestData.addProperty("type", "dhvaluereq");
    requestData.addProperty("nonce", cProps.rndHelper.getString(16, true));
    requestData.addProperty("destiny_uuid", destinationId);

    socket.getOutputStream().write(cProps.GSON.toJson(requestData).getBytes());

    JsonObject jsonObject = cProps.receiveRequest();
    RequestDestinyDHvalue req = cProps.GSON.fromJson(jsonObject, RequestDestinyDHvalue.class);
    X509Certificate certificate = (X509Certificate) socket.getSession().getPeerCertificates()[0];
    //validar assinatura
    PublicKey publicKeyserv = certificate.getPublicKey();
    cProps.aeaHelper.verifySignature(publicKeyserv, req.getDhdentinyvalue().getBytes(), req.getSecdata().getBytes());

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
*/

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

  private static SSLContext buildSSLContext(KSHelper ksHelper, KSHelper tsHelper) throws GeneralSecurityException {
    KeyManagerFactory keyManagerFactory = ksHelper.getKeyManagerFactory();
    TrustManagerFactory trustManagerFactory = tsHelper.getTrustManagerFactory();
    KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
    TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(keyManagers, trustManagers, new SecureRandom());

    return sslContext;
  }

  private static void checkNonce(String sent, String received) throws ClientException {
    if (!sent.equals(received))
      throw new ClientException("Server replied with invalid nonce.");
  }

  private static void checkNonce(JsonObject jsonObject, String received) throws ClientException {
    if (!jsonObject.get("nonce").getAsString().equals(received))
      throw new ClientException("Server replied with invalid nonce.");
  }

  private static void printCommands() {
    System.out.println(
        "CREATE <username>" + "\n" +
            "LIST (userId)?" + "\n" +
            "NEW <messageBoxOwnerId>" + "\n" +
            "ALL <messageBoxOwnerId>" + "\n" +
            "SEND <destinationId> <messageText> (<attachmentFilePath>)*" + "\n" +
            "RECEIVE <messageBoxOwnerId>" + "\n" +
            "STATUS <messageId>" + "\n" +
            "LOGIN <username" + "\n" +
            "HELP" + "\n" +
            "EXIT" + "\n"
    );
  }

  /*
    UTILS
  */
  private static void verifyUserSecDataSignature(User user, ClientProperties cProps) throws IOException, ClientException {
    try {
      byte[] pubKeyDecoded = cProps.b64Helper.decode(user.getPubKey());
      PublicKey userPublicKey = cProps.aeaHelper.pubKeyFromBytes(pubKeyDecoded);

      cProps.aeaHelper.verifySignature(
          userPublicKey,
          CryptUtil.joinByteArrays(
              cProps.b64Helper.decode(user.getDhSeaPubKey()),
              cProps.b64Helper.decode(user.getDhMacPubKey()),
              user.getSeaSpec().getBytes(),
              user.getMacSpec().getBytes()
          ),
          cProps.b64Helper.decode(user.getSecDataSignature())
      );
    } catch (SignatureException | InvalidKeyException | InvalidKeySpecException e) {
      throw new ClientException("Failed to verify user security data signature: " + e.getClass().getName() + ".");
    }
  }

  private static String getCurrentDate() {
    DateFormat df = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");

    return df.format(new Date());
  }
}
