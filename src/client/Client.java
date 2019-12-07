package client;

import client.props.ClientProperty;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.stream.JsonReader;
import org.bouncycastle.asn1.x9.DHPublicKey;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import server.db.ServerParameterMap;
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
import java.util.ArrayList;

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
      KeyStore tstore = getTrustStore(properties);

      // Create SSL Socket
      int serverport = properties.getInt(ClientProperty.SERVER_PORT);
      SSLContext sslContext = buildSSLContext(properties, keyStore);
      SSLSocketFactory factory = sslContext.getSocketFactory();
      SSLSocket socket = (SSLSocket) factory.createSocket("localhost", serverport);
      // Set enabled protocols and cipher suites
      String[] enabledProtocols = properties.getStringArr(ClientProperty.TLS_PROTOCOLS);
      String[] enabledCipherSuites = properties.getStringArr(ClientProperty.TLS_CIPHERSUITES);
      socket.setEnabledProtocols(enabledProtocols);
      socket.setEnabledCipherSuites(enabledCipherSuites);
      ClientProperties cp = new ClientProperties(properties, keyStore, tstore);


      socket.startHandshake();


      JsonObject jsonObject = requestParam(socket, cp);

      ServerParameterMap spm = cp.GSON.fromJson(jsonObject.toString(), ServerParameterMap.class);
      ClientDHHelper cdhhelper = new ClientDHHelper(spm);

      //checks user command
      String command = args[0];
      switch (command.toLowerCase()) {
        case "create":
          createUser(cdhhelper, socket, cp, properties, keyStore);
        case "list":
          list(cdhhelper, socket, cp, properties, keyStore);
          break;
        case "new":
          listNew(cdhhelper, socket, cp, properties, keyStore);
          break;
        case "all":
          listall(cdhhelper, socket, cp, properties, keyStore);
          break;
        case "send":
          //missing message encryption
          send(cdhhelper, socket, cp, properties, keyStore);
        case "recv":
          //missing message decryption
          //contem o receipt, receipt enviado dps de ler
          receive(cdhhelper, socket, cp, properties, keyStore);
          break;
        case "status":
          status(cdhhelper, socket, cp, properties, keyStore);
          break;
      }


      System.out.print("Connected to server " + serverport + "\n");
    } catch (GeneralSecurityException e) {
      //not the same signature
    } catch (Exception e) {
      handleException(e, false);
    } finally {
      System.exit(-1);
    }

  }

  private static void receive(ClientDHHelper cdhhelper, SSLSocket socket, ClientProperties cp, CustomProperties properties, KeyStore keyStore) throws IOException, InvalidFormatException {
    JsonObject requestData = new JsonObject();
    requestData.addProperty("type", "recv");
    requestData.addProperty("nonce", CryptUtil.randomBytes(16).toString());

    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));
    int messageid = Integer.parseInt(bf.readLine());
    requestData.addProperty("userId", messageid);

    socket.getOutputStream().write(cp.GSON.toJson(requestData).getBytes());
    JsonReader input = new JsonReader(new SafeInputStreamReader(socket.getInputStream(), cp.getBufferSizeInMB()));
    JsonObject obj = GsonUtils.parseRequest(input);
    Gson g = new Gson();
    ReceiveMessageResponse lmr = g.fromJson(obj, ReceiveMessageResponse.class);
    Message m = lmr.getMessage();
    //substituido depois pela chave publica para verificar assinatura
    String integrity = m.macHash;
    String text = m.text;
    int sentFrom = m.senderId;
    int mid = m.id;

    //verificacao de assinatura

    //mostrar ao utilizador a mensagem
    System.out.printf("Message sent from %d with ID %d\n", sentFrom, mid);
    System.out.println(text);

    //SEND RECEIPT WITH CONTENT SIGNATURE
  }

  private static void status(ClientDHHelper cdhhelper, SSLSocket socket, ClientProperties cp, CustomProperties properties, KeyStore keyStore) throws IOException, InvalidFormatException {
    JsonObject requestData = new JsonObject();
    requestData.addProperty("type", "status");
    requestData.addProperty("nonce", CryptUtil.randomBytes(16).toString());
    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));

    int messageid = Integer.parseInt(bf.readLine());
    requestData.addProperty("userId", messageid);
    socket.getOutputStream().write(cp.GSON.toJson(requestData).getBytes());
    JsonReader input = new JsonReader(new SafeInputStreamReader(socket.getInputStream(), cp.getBufferSizeInMB()));
    JsonObject obj = GsonUtils.parseRequest(input);
    Gson g = new Gson();
    MessageReceiptsResponse lmr = g.fromJson(obj, MessageReceiptsResponse.class);
    System.out.println("Showing status for message: " + lmr.getMessage().id);
    for (Receipt r : lmr.getReceipts()) {
      System.out.println("Sent from: " + r.sender_id);
      System.out.println("Date: " + r.date);
      System.out.println("Signature: " + r.signature);
    }

  }

  private static void listNew(ClientDHHelper cdhhelper, SSLSocket socket, ClientProperties cp, CustomProperties properties, KeyStore keyStore) throws IOException, InvalidFormatException {
    JsonObject requestData = new JsonObject();
    requestData.addProperty("type", "new");
    requestData.addProperty("nonce", CryptUtil.randomBytes(16).toString());
    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));

    int userid = Integer.parseInt(bf.readLine());
    requestData.addProperty("userId", userid);
    socket.getOutputStream().write(cp.GSON.toJson(requestData).getBytes());

    JsonReader input = new JsonReader(new SafeInputStreamReader(socket.getInputStream(), cp.getBufferSizeInMB()));
    JsonObject obj = GsonUtils.parseRequest(input);
    Gson g = new Gson();
    ListNewMessagesResponse lmr = g.fromJson(obj, ListNewMessagesResponse.class);
    System.out.println("New messages:");
    for (int s : lmr.getNewMessageIds()) {
      System.out.println("Message id: " + s);
    }

  }

  private static void listall(ClientDHHelper cdhhelper, SSLSocket socket, ClientProperties cp, CustomProperties properties, KeyStore keyStore) throws IOException, InvalidFormatException {
    JsonObject requestData = new JsonObject();
    requestData.addProperty("type", "all");
    requestData.addProperty("nonce", CryptUtil.randomBytes(16).toString());
    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));

    int userid = Integer.parseInt(bf.readLine());
    requestData.addProperty("userId", userid);
    socket.getOutputStream().write(cp.GSON.toJson(requestData).getBytes());

    JsonReader input = new JsonReader(new SafeInputStreamReader(socket.getInputStream(), cp.getBufferSizeInMB()));
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

  private static void list(ClientDHHelper cdhhelper, SSLSocket socket, ClientProperties cp, CustomProperties properties, KeyStore keyStore) throws IOException, InvalidFormatException {
    JsonObject requestData = new JsonObject();
    requestData.addProperty("type", "list");
    requestData.addProperty("nonce", CryptUtil.randomBytes(16).toString());
    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));
    int userid;
    try {
      userid = Integer.parseInt(bf.readLine());
      requestData.addProperty("userId", userid);
    } catch (IOException e) {
      //keep runnin
    }
    socket.getOutputStream().write(cp.GSON.toJson(requestData).getBytes());

    //response
    JsonReader input = new JsonReader(new SafeInputStreamReader(socket.getInputStream(), cp.getBufferSizeInMB()));
    JsonObject obj = GsonUtils.parseRequest(input);
    Gson g = new Gson();
    ListUsersResponse lur = g.fromJson(obj, ListUsersResponse.class);
    ArrayList<User> l = g.fromJson(lur.getUsers(), (Type) new ArrayList<User>() {
    }.getClass());
    System.out.println("Listing users");
    for (User user : l) {
      System.out.printf("User id : %s \t User uuid : %s\n", user.id, user.uuid);
    }


  }

  private static void send(ClientDHHelper cdhhelper, SSLSocket socket, ClientProperties cp, CustomProperties properties, KeyStore keyStore) throws IOException, InvalidFormatException, GeneralSecurityException, PropertyException {
    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));
    JsonObject requestData = new JsonObject();
    requestData.addProperty("type", "send");
    requestData.addProperty("nonce", CryptUtil.randomBytes(16).toString());
    int uuid = Integer.parseInt(bf.readLine());
    requestData.addProperty("source", uuid);

    int destinUuid = Integer.parseInt(bf.readLine());
    requestData.addProperty("destination", destinUuid);

    String text = bf.readLine();

    if (!checkanotherUserDHkey(keyStore, uuid, destinUuid, properties)) {
      saveAnotherUserDHkey(properties, keyStore, uuid, destinUuid, socket, cp);
    }

    //load shared key
    keyStore.getKey(uuid + "-" + destinUuid + "-shared", properties.getString(ClientProperty.TRUSTSTORE_PASS).toCharArray());

  }

  private static void createUser(ClientDHHelper cdhhelper, SSLSocket socket, ClientProperties cp, CustomProperties properties, KeyStore keyStore) throws IOException, GeneralSecurityException, PropertyException, InvalidFormatException {
    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));
    JsonObject requestData = new JsonObject();
    requestData.addProperty("type", "create");
    requestData.addProperty("nonce", CryptUtil.randomBytes(16).toString());

    String uuid = bf.readLine();
    requestData.addProperty("uuid", uuid);

    byte[] dhpublickeybytes = createmyDH(cp, uuid, cdhhelper, properties, keyStore);
    requestData.addProperty("dhValue", String.valueOf(dhpublickeybytes));
    PrivateKey privateKey = cp.privateKey();
    byte[] paramsJSONSigBytes = cp.AEA.sign(privateKey, dhpublickeybytes);
    requestData.addProperty("secDataSignature", String.valueOf(paramsJSONSigBytes));

    socket.getOutputStream().write(cp.GSON.toJson(requestData).getBytes());

    JsonReader input = new JsonReader(new SafeInputStreamReader(socket.getInputStream(), cp.getBufferSizeInMB()));
    JsonObject obj = GsonUtils.parseRequest(input);
    Gson g = new Gson();
    CreateUserResponse resp = g.fromJson(obj, CreateUserResponse.class);

    System.out.println("User_ID: " + resp.getUserId());

  }

  private static byte[] createmyDH(ClientProperties cp, String uuid, ClientDHHelper cdhhelper, CustomProperties properties, KeyStore keyStore) throws GeneralSecurityException, PropertyException, IOException {
    BigInteger p = new BigInteger(cdhhelper.getDh_p());
    BigInteger g = new BigInteger(cdhhelper.getDh_g());
    DHParameterSpec dhspec = new DHParameterSpec(p, g);

    KeyPair kp = cp.DH.genKeyPair(dhspec);

    KeyStore.SecretKeyEntry dhprivkey = new KeyStore.SecretKeyEntry((SecretKey) kp.getPrivate());
    KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(properties.getString(ClientProperty.KEYSTORE_PASS).toCharArray());
    keyStore.setEntry(uuid + "-priv", dhprivkey, protectionParam);
    keyStore.store(new FileOutputStream(new File(properties.getString(ClientProperty.KEYSTORE_LOC))), properties.getString(ClientProperty.KEYSTORE_PASS).toCharArray());

    BigInteger pubKeyBI = ((DHPublicKey) kp.getPublic()).getY();
    return pubKeyBI.toByteArray();
  }

  private static KeyStore getTrustStore(CustomProperties properties) throws PropertyException, IOException, GeneralSecurityException {
    String keyStoreLoc = properties.getString(ClientProperty.TRUSTSTORE_LOC);
    String keyStorePass = properties.getString(ClientProperty.TRUSTSTORE_PASS);
    String keyStoreType = properties.getString(ClientProperty.TRUSTSTORE_TYPE);

    return CryptUtil.loadKeystore(keyStoreLoc, keyStoreType, keyStorePass.toCharArray());
  }


  private static JsonObject requestParam(SSLSocket sslSocket, ClientProperties clientProperties) throws IOException, InvalidFormatException, GeneralSecurityException {
    JsonObject requestData = new JsonObject();
    //vai explodir no server devido a nao ter o decode b64
    requestData.addProperty("type", "params");
    requestData.addProperty("nonce", CryptUtil.randomBytes(16).toString());
    sslSocket.getOutputStream().write(clientProperties.GSON.toJson(requestData).getBytes());

    //parses answer from server
    JsonReader input = new JsonReader(new SafeInputStreamReader(sslSocket.getInputStream(), clientProperties.getBufferSizeInMB()));
    JsonObject obj = GsonUtils.parseRequest(input);
    Gson g = new Gson();
    ParametersResponse response = g.fromJson(obj.toString(), ParametersResponse.class);
    X509Certificate certificate = (X509Certificate) sslSocket.getSession().getPeerCertificates()[0];

    //validate signature
    PublicKey publicKey = certificate.getPublicKey();
    clientProperties.AEA.verifySignature(publicKey, response.getParameters().getBytes(), response.getSignature().getBytes());
    //gets the json
    return clientProperties.GSON.fromJson(response.getParameters(), JsonObject.class);
  }

  //checks if x user has a in its ks y users dh generated key
  private static boolean checkanotherUserDHkey(KeyStore keyStore, int uuid, int destinUuid, CustomProperties properties) throws PropertyException {
    try {
      keyStore.getKey(uuid + "-" + destinUuid + "-shared", properties.getString(ClientProperty.TRUSTSTORE_PASS).toCharArray());
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  private static void saveAnotherUserDHkey(CustomProperties cp, KeyStore ks, int src, int destinUuid, SSLSocket socket, ClientProperties clientProperties) throws IOException, InvalidFormatException, GeneralSecurityException, PropertyException {
    JsonObject requestData = new JsonObject();
    requestData.addProperty("type", "dhvaluereq");
    requestData.addProperty("nonce", CryptUtil.randomBytes(16).toString());
    requestData.addProperty("destiny_uuid", destinUuid);

    socket.getOutputStream().write(clientProperties.GSON.toJson(requestData).getBytes());

    JsonReader input = new JsonReader(new SafeInputStreamReader(socket.getInputStream(), clientProperties.getBufferSizeInMB()));
    JsonObject obj = GsonUtils.parseRequest(input);
    Gson g = new Gson();
    RequestDestinyDHvalue req = g.fromJson(obj.toString(), RequestDestinyDHvalue.class);
    X509Certificate certificate = (X509Certificate) socket.getSession().getPeerCertificates()[0];
    //validar assinatura
    PublicKey publicKeyserv = certificate.getPublicKey();
    clientProperties.AEA.verifySignature(publicKeyserv, req.getDhdentinyvalue().getBytes(), req.getSecdata().getBytes());

    KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");
    PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(req.getDhdentinyvalue().getBytes()));

    //generate shared key between src - dst
    KeyAgreement keyAgree = KeyAgreement.getInstance("DiffieHellman");
    PrivateKey pk = (PrivateKey) ks.getKey(src + "-priv", cp.getString(ClientProperty.KEYSTORE_PASS).toCharArray());
    keyAgree.init(pk);
    keyAgree.doPhase(publicKey, true);
    byte[] sharedKeyBytes = keyAgree.generateSecret();

    //gravar na keystore
    PrivateKey shared = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(sharedKeyBytes));
    KeyStore.SecretKeyEntry sharedkeyentry = new KeyStore.SecretKeyEntry((SecretKey) shared);
    KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(cp.getString(ClientProperty.KEYSTORE_PASS).toCharArray());
    ks.setEntry(src + "-" + destinUuid + "-shared", sharedkeyentry, protectionParam);
    ks.store(new FileOutputStream(new File(cp.getString(ClientProperty.KEYSTORE_LOC))), cp.getString(ClientProperty.KEYSTORE_PASS).toCharArray());


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

    TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("X509", CryptUtil.PROVIDER_TLS);
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

    KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("X509", CryptUtil.PROVIDER_TLS);
    keyManagerFactory.init(keyStore, keyStorePass.toCharArray());

    return keyManagerFactory;
  }

  private static SSLContext buildSSLContext(CustomProperties properties, KeyStore keyStore) throws GeneralSecurityException, IOException, PropertyException {
    // Build default context for use with custom trust manager (OCSP) Extension
    KeyManagerFactory keyManagerFactory = getKeyManagerFactory(properties, keyStore);
    TrustManagerFactory trustManagerFactory = getTrustManagerFactory(properties);
    KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
    TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

    SSLContext sslContext = SSLContext.getInstance("TLS", CryptUtil.PROVIDER_TLS);
    sslContext.init(keyManagers, trustManagers, new SecureRandom());

    return sslContext;
  }

}
