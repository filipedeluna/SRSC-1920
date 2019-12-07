package client;

import client.props.ClientProperty;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.stream.JsonReader;
import org.bouncycastle.asn1.x9.DHPublicKey;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import shared.ServerRequest;
import shared.parameters.ServerParameterMap;
import server.db.wrapper.Message;
import server.db.wrapper.Receipt;
import server.db.wrapper.User;
import server.response.*;
import shared.errors.properties.PropertyException;
import shared.errors.request.InvalidFormatException;
import shared.utils.CryptUtil;
import shared.utils.GsonUtils;
import shared.utils.SafeInputStreamReader;
import shared.utils.properties.CustomProperties;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.net.ssl.*;
import java.io.*;
import java.lang.reflect.Type;
import java.math.BigInteger;
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
      KeyStore keyStore = getKeyStore(properties);
      KeyStore trustStore = getTrustStore(properties);

      // Create SSL Socket
      int serverPort = properties.getInt(ClientProperty.SERVER_PORT);
      SSLContext sslContext = buildSSLContext(properties, keyStore);
      SSLSocketFactory factory = sslContext.getSocketFactory();
      SSLSocket socket = (SSLSocket) factory.createSocket("localhost", serverPort);

      // Set enabled protocols and cipher suites
      String[] enabledProtocols = properties.getStringArr(ClientProperty.TLS_PROTOCOLS);
      String[] enabledCipherSuites = properties.getStringArr(ClientProperty.TLS_CIPHERSUITES);
      socket.setEnabledProtocols(enabledProtocols);
      socket.setEnabledCipherSuites(enabledCipherSuites);

      // Create client properties
      ClientProperties cProps = new ClientProperties(properties, keyStore, trustStore);

      // Start SSL socket handshake with server and request shared parameters
      socket.startHandshake();
      JsonObject serverParamsJSON = requestParams(socket, cProps);

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
          createUser(socket, cProps, requestData);
        case LIST:
          listUsers(socket, cProps, requestData);
          break;
        case NEW:
          listNewMessages(socket, cProps, requestData);
          break;
        case ALL:
          listAllMessages(socket, cProps, requestData);
          break;
        case SEND:
          //missing message encryption
          sendMessages(socket, cProps, requestData);
        case RECEIVE:
          //missing message decryption
          //contem o receipt, receipt enviado dps de ler
          receiveMessages(socket, cProps, requestData);
          break;
        case STATUS:
          status(socket, cProps, requestData);
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

  private static void receiveMessages(SSLSocket socket, ClientProperties cProps, JsonObject requestData) throws IOException, InvalidFormatException {
    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));
    int messageid = Integer.parseInt(bf.readLine());
    requestData.addProperty("userId", messageid);

    socket.getOutputStream().write(cProps.GSON.toJson(requestData).getBytes());
    JsonReader input = new JsonReader(new SafeInputStreamReader(socket.getInputStream(), cProps.getBufferSizeInMB()));
    JsonObject obj = GsonUtils.parseRequest(input);
    Gson g = new Gson();
    ReceiveMessageResponse lmr = g.fromJson(obj, ReceiveMessageResponse.class);
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

  private static void status(SSLSocket socket, ClientProperties cProps, JsonObject requestData) throws IOException, InvalidFormatException {
    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));

    int messageid = Integer.parseInt(bf.readLine());
    requestData.addProperty("userId", messageid);
    socket.getOutputStream().write(cProps.GSON.toJson(requestData).getBytes());
    JsonReader input = new JsonReader(new SafeInputStreamReader(socket.getInputStream(), cProps.getBufferSizeInMB()));
    JsonObject obj = GsonUtils.parseRequest(input);
    Gson g = new Gson();
    MessageReceiptsResponse lmr = g.fromJson(obj, MessageReceiptsResponse.class);
    System.out.println("Showing status for message: " + lmr.getMessage().getId());
    for (Receipt r : lmr.getReceipts()) {
      System.out.println("Date: " + r.getDate());
      System.out.println("Signature: " + r.getReceiverSignature());
    }

  }

  private static void listNewMessages(SSLSocket socket, ClientProperties cProps, JsonObject requestData) throws IOException, InvalidFormatException {
    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));

    int userid = Integer.parseInt(bf.readLine());
    requestData.addProperty("userId", userid);
    socket.getOutputStream().write(cProps.GSON.toJson(requestData).getBytes());

    JsonReader input = new JsonReader(new SafeInputStreamReader(socket.getInputStream(), cProps.getBufferSizeInMB()));
    JsonObject obj = GsonUtils.parseRequest(input);
    Gson g = new Gson();
    ListNewMessagesResponse lmr = g.fromJson(obj, ListNewMessagesResponse.class);
    System.out.println("New messages:");
    for (int s : lmr.getNewMessageIds()) {
      System.out.println("Message id: " + s);
    }

  }

  private static void listAllMessages(SSLSocket socket, ClientProperties cProps, JsonObject requestData) throws IOException, InvalidFormatException {
    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));

    int userid = Integer.parseInt(bf.readLine());
    requestData.addProperty("userId", userid);
    socket.getOutputStream().write(cProps.GSON.toJson(requestData).getBytes());

    JsonReader input = new JsonReader(new SafeInputStreamReader(socket.getInputStream(), cProps.getBufferSizeInMB()));
    JsonObject obj = GsonUtils.parseRequest(input);
    Gson g = new Gson();
    ListMessagesResponse lmr = g.fromJson(obj, ListMessagesResponse.class);

    System.out.println("Received:");
    for (String s : lmr.getReceivedMessageIds()) {
      System.out.println("Message id: " + s);
    }
    System.out.println("Sent:");
    for (int s : lmr.getSentMessageIds()) {
      System.out.println("Message id: " + s);
    }

  }

  private static User listUsers(SSLSocket socket, ClientProperties cProps, JsonObject requestData) throws IOException, InvalidFormatException {
    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));
    int userid = 0;
    boolean u = true;
    try {
      userid = Integer.parseInt(bf.readLine());
      requestData.addProperty("userId", userid);
    } catch (IOException e) {
      u = false;
    }
    socket.getOutputStream().write(cProps.GSON.toJson(requestData).getBytes());

    //response
    JsonReader input = new JsonReader(new SafeInputStreamReader(socket.getInputStream(), cProps.getBufferSizeInMB()));
    JsonObject obj = GsonUtils.parseRequest(input);
    Gson g = new Gson();
    ListUsersResponse lur = g.fromJson(obj, ListUsersResponse.class);
    ArrayList<User> l = g.fromJson(lur.getUsers(), (Type) new ArrayList<User>() {
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

  private static void sendMessages(SSLSocket socket, ClientProperties cProps, JsonObject requestData) throws IOException, InvalidFormatException, GeneralSecurityException, PropertyException {
    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));

    int uuid = Integer.parseInt(bf.readLine());
    requestData.addProperty("source", uuid);

    int destinUuid = Integer.parseInt(bf.readLine());
    requestData.addProperty("destination", destinUuid);

    String text = bf.readLine();

    if (!checkAnotherUserDHkey(cProps, uuid, destinUuid)) {
      saveAnotherUserDHkey(cProps.KEYSTORE, uuid, destinUuid, socket, cProps);
    }

    //load shared key
    cProps.KEYSTORE.getKey(uuid + "-" + destinUuid + "-shared", cProps.keyStorePassword());

  }

  private static void createUser(SSLSocket socket, ClientProperties cProps, JsonObject requestData) throws IOException, GeneralSecurityException, PropertyException, InvalidFormatException {
    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));

    String uuid = bf.readLine();
    requestData.addProperty("uuid", uuid);

    byte[] dhpublickeybytes = createMyDH(cProps, uuid, cProps.KEYSTORE);
    requestData.addProperty("dhValue", String.valueOf(dhpublickeybytes));
    requestData.addProperty("seaSpec", cProps.SEASPEC);

    PrivateKey privateKey = cProps.privateKey();
    byte[] paramsJSONSigBytes = cProps.AEAHelper.sign(privateKey, dhpublickeybytes);
    requestData.addProperty("secDataSignature", String.valueOf(paramsJSONSigBytes));

    socket.getOutputStream().write(cProps.GSON.toJson(requestData).getBytes());

    JsonReader input = new JsonReader(new SafeInputStreamReader(socket.getInputStream(), cProps.getBufferSizeInMB()));
    JsonObject obj = GsonUtils.parseRequest(input);
    Gson g = new Gson();
    CreateUserResponse resp = g.fromJson(obj, CreateUserResponse.class);

    System.out.println("User_ID: " + resp.getUserId());

  }

  private static byte[] createMyDH(ClientProperties cProps, String uuid, KeyStore keyStore) throws GeneralSecurityException, PropertyException, IOException {
    // Generate Parameter Spec and create keypair
    DHParameterSpec dhSpec = new DHParameterSpec(cProps.DHHelper.getP(), cProps.DHHelper.getG());
    KeyPair kp = cProps.DHHelper.genKeyPair(dhSpec);

    KeyStore.SecretKeyEntry dhPrivKey = new KeyStore.SecretKeyEntry((SecretKey) kp.getPrivate());
    KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(cProps.keyStorePassword());
    keyStore.setEntry(uuid + "-priv", dhPrivKey, protectionParam);
    keyStore.store(new FileOutputStream(new File(cProps.KEYSTORE_LOC)), cProps.keyStorePassword());

    BigInteger pubKeyBI = ((DHPublicKey) kp.getPublic()).getY();
    return pubKeyBI.toByteArray();
  }

  private static KeyStore getTrustStore(CustomProperties properties) throws PropertyException, IOException, GeneralSecurityException {
    String keyStoreLoc = properties.getString(ClientProperty.TRUSTSTORE_LOC);
    String keyStorePass = properties.getString(ClientProperty.TRUSTSTORE_PASS);
    String keyStoreType = properties.getString(ClientProperty.TRUSTSTORE_TYPE);

    return CryptUtil.loadKeystore(keyStoreLoc, keyStoreType, keyStorePass.toCharArray());
  }

  private static JsonObject requestParams(SSLSocket sslSocket, ClientProperties cProps) throws IOException, InvalidFormatException, GeneralSecurityException {
    JsonObject requestData = new JsonObject();
    //vai explodir no server devido a nao ter o decode b64
    requestData.addProperty("type", "params");
    requestData.addProperty("nonce", cProps.RNDHelper.getString(16, true));
    sslSocket.getOutputStream().write(cProps.GSON.toJson(requestData).getBytes());

    //parses answer from server
    JsonReader input = new JsonReader(new SafeInputStreamReader(sslSocket.getInputStream(), cProps.getBufferSizeInMB()));
    JsonObject obj = GsonUtils.parseRequest(input);
    Gson g = new Gson();
    ParametersResponse response = g.fromJson(obj.toString(), ParametersResponse.class);
    X509Certificate certificate = (X509Certificate) sslSocket.getSession().getPeerCertificates()[0];

    //validate signature
    PublicKey publicKey = certificate.getPublicKey();
    cProps.AEAHelper.verifySignature(publicKey, response.getParameters().getBytes(), response.getSignature().getBytes());
    //gets the json
    return cProps.GSON.fromJson(response.getParameters(), JsonObject.class);
  }

  //checks if x user has a in its ks y users dh generated key
  // TODO DH keys are stored in keystore not truststore... truststores are not safe
  private static boolean checkAnotherUserDHkey(ClientProperties cProps, int uuid, int destinUuid) {
    try {
      cProps.KEYSTORE.getKey(uuid + "-" + destinUuid + "-shared", cProps.keyStorePassword());
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  private static void saveAnotherUserDHkey(KeyStore keyStore, int src, int destinUuid, SSLSocket socket, ClientProperties cProps) throws IOException, InvalidFormatException, GeneralSecurityException, PropertyException {
    JsonObject requestData = new JsonObject();
    requestData.addProperty("type", "dhvaluereq");
    requestData.addProperty("nonce", cProps.RNDHelper.getString(16, true));
    requestData.addProperty("destiny_uuid", destinUuid);

    socket.getOutputStream().write(cProps.GSON.toJson(requestData).getBytes());

    JsonReader input = new JsonReader(new SafeInputStreamReader(socket.getInputStream(), cProps.getBufferSizeInMB()));
    JsonObject obj = GsonUtils.parseRequest(input);
    Gson g = new Gson();
    RequestDestinyDHvalue req = g.fromJson(obj.toString(), RequestDestinyDHvalue.class);
    X509Certificate certificate = (X509Certificate) socket.getSession().getPeerCertificates()[0];
    //validar assinatura
    PublicKey publicKeyserv = certificate.getPublicKey();
    cProps.AEAHelper.verifySignature(publicKeyserv, req.getDhdentinyvalue().getBytes(), req.getSecdata().getBytes());

    KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");
    PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(req.getDhdentinyvalue().getBytes()));

    //generate shared key between src - dst
    KeyAgreement keyAgree = KeyAgreement.getInstance("DiffieHellman");
    PrivateKey pk = (PrivateKey) keyStore.getKey(src + "-priv", cProps.keyStorePassword());
    keyAgree.init(pk);
    keyAgree.doPhase(publicKey, true);
    byte[] sharedKeyBytes = keyAgree.generateSecret();

    //gravar na keystore
    PrivateKey shared = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(sharedKeyBytes));
    KeyStore.SecretKeyEntry sharedkeyentry = new KeyStore.SecretKeyEntry((SecretKey) shared);
    KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(cProps.keyStorePassword());
    keyStore.setEntry(src + "-" + destinUuid + "-shared", sharedkeyentry, protectionParam);
    keyStore.store(new FileOutputStream(new File(cProps.KEYSTORE_LOC)), cProps.keyStorePassword());
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

  private static TrustManagerFactory getTrustManagerFactory(CustomProperties properties) throws PropertyException, GeneralSecurityException, IOException {
    String trustStoreLoc = properties.getString(ClientProperty.TRUSTSTORE_LOC);
    String trustStorePass = properties.getString(ClientProperty.TRUSTSTORE_PASS);
    String trustStoreType = properties.getString(ClientProperty.TRUSTSTORE_TYPE);

    KeyStore trustStore = CryptUtil.loadKeystore(trustStoreLoc, trustStoreType, trustStorePass.toCharArray());

    TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("X509", properties.getString(ClientProperty.PROVIDER));
    trustManagerFactory.init(trustStore);

    return trustManagerFactory;
  }

  private static KeyStore getKeyStore(CustomProperties properties) throws PropertyException, GeneralSecurityException, IOException {
    String keyStoreLoc = properties.getString(ClientProperty.KEYSTORE_LOC);
    String keyStorePass = properties.getString(ClientProperty.KEYSTORE_PASS);
    String keyStoreType = properties.getString(ClientProperty.KEYSTORE_TYPE);

    return CryptUtil.loadKeystore(keyStoreLoc, keyStoreType, keyStorePass.toCharArray());
  }

  private static KeyManagerFactory getKeyManagerFactory(CustomProperties properties, KeyStore keyStore) throws PropertyException, GeneralSecurityException {
    String keyStorePass = properties.getString(ClientProperty.KEYSTORE_PASS);

    KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("X509", properties.getString(ClientProperty.PROVIDER));
    keyManagerFactory.init(keyStore, keyStorePass.toCharArray());

    return keyManagerFactory;
  }

  private static SSLContext buildSSLContext(CustomProperties properties, KeyStore keyStore) throws GeneralSecurityException, IOException, PropertyException {
    KeyManagerFactory keyManagerFactory = getKeyManagerFactory(properties, keyStore);
    TrustManagerFactory trustManagerFactory = getTrustManagerFactory(properties);
    KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
    TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

    SSLContext sslContext = SSLContext.getInstance("TLS", properties.getString(ClientProperty.PROVIDER));
    sslContext.init(keyManagers, trustManagers, new SecureRandom());

    return sslContext;
  }

  /*
    UTILS
  */
  private String getCurrentDate() {
    DateFormat df = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");

    return df.format(new Date());
  }
}
