package client;

import client.cache.UserCacheEntry;
import client.crypt.DHKeyType;
import client.errors.ClientException;
import client.props.ClientProperty;
import client.utils.ClientRequest;
import com.google.gson.JsonObject;
import shared.parameters.ServerParameterMap;
import shared.utils.Utils;
import shared.wrappers.Message;
import shared.wrappers.User;
import shared.errors.properties.PropertyException;
import shared.parameters.ServerParameterType;
import shared.response.server.*;
import shared.utils.crypto.KSHelper;
import shared.utils.properties.CustomProperties;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DHParameterSpec;
import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
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
      SSLContext sslContext = buildSSLContext(ksHelper, tsHelper);
      SSLSocketFactory factory = sslContext.getSocketFactory();
      SSLSocket socket = createSocket(factory, properties);

      // Start handshake
      System.out.println("SSL setup finished.");
      socket.startHandshake();
      System.out.println("Handshake completed.");

      // Create client properties and connect/input output
      ClientProperties cProps = new ClientProperties(properties, ksHelper, tsHelper);
      cProps.connect(socket);

      // Request shared parameters and that initialize dh and aea helpers
      ServerParameterMap spm = requestParams(cProps);


      // Command reader
      BufferedReader lineReader = new BufferedReader(new InputStreamReader(System.in));

      // Close the socket
      socket.close();

      while (true) {
        try {
          // Restart connection for new request with new socket and connect i/o
          socket = createSocket(factory, properties);
          socket.startHandshake();
          cProps.connect(socket);

          System.out.println();
          System.out.println("Enter command: ");

          // Read line commands and parse
          String[] cmdArgs = lineReader.readLine().split(" (?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");

          // Parse and validate request and create resquest object
          ClientRequest request = ClientRequest.fromString(cmdArgs[0]);
          JsonObject requestData = new JsonObject();

          // Check request is valid and argument length correct
          if (request == null)
            throw new ClientException("Invalid command.");

          if (!request.checkArgs((cmdArgs.length)))
            throw new ClientException("Invalid command arguments.");

          // Initialize request object with request type
          requestData.addProperty("type", request.val());

          // Get nonce if supposed to for the requested route
          if (request.needsNonce())
            requestData.addProperty("nonce", cProps.rndHelper.getNonce());

          switch (request) {
            case CREATE:
              createUser(cProps, requestData, cmdArgs);
              break;
            case LIST:
              listUsers(cProps, requestData, cmdArgs);
              break;
            case NEW:
              listNewMessages(cProps, requestData, cmdArgs);
              break;
            case ALL:
              listAllMessages(cProps, requestData, cmdArgs);
              break;
            case SEND:
              //missing message encryption
              sendMessages(cProps, requestData, cmdArgs);
              break;
            case RECV:
              // TODO missing message decryption
              //contem o receipt, receipt enviado dps de ler
              receiveMessages(cProps, requestData, cmdArgs);
              break;
            case STATUS:
              status(cProps, requestData, cmdArgs);
              break;
            case LOGIN:
              login(cProps, requestData, cmdArgs);
              break;
            case HELP:
              printCommands();
              break;
            case EXIT:
              System.out.println("Exited the client.");
              System.exit(0);
              break;
          }

          socket.close();
        } catch (ClientException e) {
          System.err.println(e.getMessage());
          e.printStackTrace();
        } catch (ClassCastException e) {
          System.err.println("Received an invalid format message.");
        }
      }
    } catch (Exception e) {
      System.err.println("CRITICAL ERROR: " + e.getMessage());
      e.printStackTrace();
      System.exit(-1);
    }
  }

  private static void login(ClientProperties cProps, JsonObject requestData, String[] args) throws ClientException, IOException {
    // Get username, compute uuid and add to request
    String username = args[1].trim();
    String uuid = cProps.generateUUID(username);
    requestData.addProperty("uuid", uuid);

    cProps.sendRequest(requestData);

    // Get response and check nonce
    LoginResponse resp = cProps.receiveRequestWithNonce(requestData, LoginResponse.class);

    // Get user details from response and check data signature
    User user = resp.getUser();

    if (user == null)
      throw new ClientException("No user found with username " + username + ".");

    PublicKey userPubKey = verifyUserSecDataSignature(user, cProps);

    // Check if user dh keys exist
    if (!cProps.ksHelper.dhKeyPairExists(username, DHKeyType.SEA) || !cProps.ksHelper.dhKeyPairExists(username, DHKeyType.MAC))
      throw new ClientException("User keys not found.");

    // Get user dh keys
    KeyPair seaDhKeyPair;
    KeyPair macDhKeyPair;
    try {
      seaDhKeyPair = cProps.ksHelper.loadDHKeyPair(username, DHKeyType.SEA);
      macDhKeyPair = cProps.ksHelper.loadDHKeyPair(username, DHKeyType.MAC);
    } catch (Exception e) {
      e.printStackTrace();
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

    // Also add user to cache
    cProps.cache.addUser(
        user.getId(),
        new UserCacheEntry(
            userPubKey,
            cProps.b64Helper.decode(user.getDhSeaPubKey()),
            cProps.b64Helper.decode(user.getDhMacPubKey()),
            user.getSeaSpec(),
            user.getMacSpec()
        )
    );

    // Also associate uuid to cache
    cProps.cache.addUUID(uuid, user.getId());

    cProps.establishSession(session);

    System.out.println("User " + username + " successfully logged in.");
  }

  // TODO OOOOOOOOOOOOOOOOO VERIFY THE NONCES EVERYWHERE

  private static ServerParameterMap requestParams(ClientProperties cProps) throws GeneralSecurityException, IOException, ClientException {
    JsonObject requestData = new JsonObject();

    // Create request parameters and send request
    requestData.addProperty("type", "params");
    String nonce = cProps.rndHelper.getNonce();
    requestData.addProperty("nonce", nonce);
    cProps.sendRequest(requestData);

    // Get response and check nonce
    ParametersResponse resp = cProps.receiveRequest(ParametersResponse.class);

    // Create parameters map class from received JSON
    ServerParameterMap paramsMap = ((ParametersResponse) resp).getParameters();

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

  private static void createUser(ClientProperties cProps, JsonObject requestData, String[] args) throws IOException, GeneralSecurityException, ClientException {
    // Generate a uuid from a users chosen username, adding entropy to it
    String username = args[1].trim();
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
    cProps.ksHelper.saveDHKeyPair(username, DHKeyType.SEA, dhSeaKeypair, cProps.dhHelper.getP(), cProps.dhHelper.getG());
    cProps.ksHelper.saveDHKeyPair(username, DHKeyType.MAC, dhMacKeypair, cProps.dhHelper.getP(), cProps.dhHelper.getG());

    // Add all security properties to the header
    byte[] seaDHPubKeyBytes = dhSeaKeypair.getPublic().getEncoded();
    byte[] macDHPubKeyBytes = dhMacKeypair.getPublic().getEncoded();

    requestData.addProperty("dhSeaPubKey", cProps.b64Helper.encode(seaDHPubKeyBytes));
    requestData.addProperty("dhMacPubKey", cProps.b64Helper.encode(macDHPubKeyBytes));
    requestData.addProperty("seaSpec", cProps.getSeaSpec());
    requestData.addProperty("macSpec", cProps.getMacSpec());

    // Get byte array of all properties and sign them
    byte[] paramsSignatureBytes = cProps.aeaHelper.sign(
        cProps.getPrivateKey(),
        seaDHPubKeyBytes,
        macDHPubKeyBytes,
        cProps.getSeaSpec().getBytes(),
        cProps.getMacSpec().getBytes()
    );

    // Add encoded signature to request and send request with JSON data
    requestData.addProperty("secDataSignature", cProps.b64Helper.encode(paramsSignatureBytes));
    cProps.sendRequest(requestData);

    // Get response and check nonce
    CreateUserResponse resp = cProps.receiveRequest(CreateUserResponse.class);


    // Get the user id and add user to cache
    int userId = resp.getUserId();

    cProps.cache.addUser(
        userId,
        new UserCacheEntry(
            cProps.getClientPublicKey(),
            seaDHPubKeyBytes,
            macDHPubKeyBytes,
            cProps.getSeaSpec(),
            cProps.getMacSpec()
        )
    );

    System.out.println("User created with id: " + userId);
  }


  private static void listUsers(ClientProperties cProps, JsonObject requestData, String[] args) throws IOException, ClientException {
    // Add id if inserted and send the request
    try {
      if (args.length == 2)
        requestData.addProperty("userId", Integer.valueOf(args[1]));
    } catch (NumberFormatException e) {
      throw new ClientException("User id has an invalid format.");
    }

    cProps.sendRequest(requestData);

    // Get response and check the nonce
    ListUsersResponse resp = cProps.receiveRequestWithNonce(requestData, ListUsersResponse.class);

    // Extract users from response an add them to the cache
    ArrayList<User> users = resp.getUsers();

    ArrayList<Integer> obtained = new ArrayList<>();
    ArrayList<Integer> failed = new ArrayList<>();

    PublicKey userPubKey;
    for (User user : users) {
      if (user == null)
        continue;


      try {
        verifyUserSecDataSignature(user, cProps);
        userPubKey = cProps.aeaHelper.pubKeyFromBytes(cProps.b64Helper.decode(user.getPubKey()));
        obtained.add(user.getId());
      } catch (ClientException | InvalidKeySpecException e) {
        if (e instanceof ClientException)
          System.out.println("Failed to validate user with id " + user.getId());
        else
          System.out.println("User with id " + user.getId() + " has a corrupted public key.");

        failed.add(user.getId());
        continue;
      }

      cProps.cache.addUser(
          user.getId(),
          new UserCacheEntry(
              userPubKey,
              cProps.b64Helper.decode(user.getDhSeaPubKey()),
              cProps.b64Helper.decode(user.getDhMacPubKey()),
              user.getSeaSpec(),
              user.getMacSpec()
          )
      );
    }

    if (obtained.size() > 0)
      System.out.println("Obtained and verified user's with ids " + obtained.toString() + " info.");

    if (failed.size() > 0)
      System.err.println("Failed to verify user's with ids " + failed.toString() + " info.");

    if (obtained.size() == 0 && failed.size() == 0)
      System.err.println("No users found.");

  }

  private static void listNewMessages(ClientProperties cProps, JsonObject requestData, String[] args) throws IOException, ClientException {
    // Add id of user to get new messages if it exists
    if (args.length > 1)
      try {
        int userId = Integer.parseInt(args[1]);
        requestData.addProperty("userId", userId);
      } catch (NumberFormatException e) {
        throw new ClientException("User id has an invalid format.");
      }

    cProps.sendRequest(requestData);

    // Get response and check the nonce
    ListNewMessagesResponse resp = cProps.receiveRequestWithNonce(requestData, ListNewMessagesResponse.class);

    // Get new message ids an print them
    System.out.println("Obtained the following unread message ids: (" + resp.getNewMessageIds().toString() + ").");
  }

  private static void listAllMessages(ClientProperties cProps, JsonObject requestData, String[] args) throws IOException, ClientException {
    // Add id of user to get new messages
    try {
      int userId = Integer.parseInt(args[1]);
      requestData.addProperty("userId", userId);
    } catch (NumberFormatException e) {
      throw new ClientException("User id has an invalid format.");
    }

    cProps.sendRequest(requestData);

    // Get response and check the nonce
    ListMessagesResponse resp = cProps.receiveRequestWithNonce(requestData, ListMessagesResponse.class);

    // Get new message ids an print them
    System.out.println("Obtained the following received message ids: (" + resp.getReceivedMessageIds().toString() + ").");
    System.out.println("Obtained the following sent message ids: (" + resp.getSentMessageIds().toString() + ").");
    System.out.println("Note: Read messages come with a prefixed \"_\".");
  }

  private static void sendMessages(ClientProperties cProps, JsonObject requestData, String[] args) throws IOException, GeneralSecurityException, ClientException, PropertyException, ClassNotFoundException {
    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));

    int clientId = Integer.parseInt(args[1]);
    requestData.addProperty("source", Integer.parseInt(args[1]));

    int destinationId = Integer.parseInt(args[2]);
    requestData.addProperty("destination", destinationId);
    System.out.println("Message:");
    String text = bf.readLine();

    Cipher seacipher;
    Cipher maccipher;

    // try to load shared key
    try {
      seacipher = loadKeyAndInitCipher(cProps, clientId, destinationId);
      maccipher = loadKeyAndInitHmacCipher(cProps, clientId, destinationId);
    } catch (InvalidKeyException | UnrecoverableKeyException | KeyStoreException e) {
      //If user cant load the ciphers, menas he does not have them, so he must create the shared key first

      //initatiates the keyagrees 1 for sea 1 for mac
      KeyAgreement keyAgreesea = createSEAAgree(cProps);
      KeyAgreement keaAgreemac = createMACAgree(cProps);

      //checks if destiny user is in cache if not gets the user
      UserCacheEntry destinyuser = checkAndGetDestinyUser(cProps, destinationId);

      seacipher = generateSeaSharedKey(cProps, clientId, keyAgreesea, destinyuser);
      maccipher = generateMACSharedKey(cProps, clientId, keyAgreesea, destinyuser);
    }

    //Encrypts data
    String encrypted = new String(seacipher.doFinal(text.getBytes()));
    requestData.addProperty("text", encrypted);

    //adds cipher iv
    requestData.addProperty("cipherIV", new String(seacipher.getIV()));

    //Produces integrity code
    String macCode = new String(maccipher.doFinal(encrypted.getBytes()));
    requestData.addProperty("senderSignature", macCode);

    cProps.sendRequest(requestData);

  }

  private static Cipher generateMACSharedKey(ClientProperties cProps, int clientId, KeyAgreement keyAgreemac, UserCacheEntry destinyuser) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, PropertyException, KeyStoreException, IOException, CertificateException {
    KeyFactory factory = KeyFactory.getInstance(cProps.dhHelper.getAlgorithm());
    X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(destinyuser.getDhSeaPubKey());
    PublicKey publicKey = factory.generatePublic(encodedKeySpec);
    keyAgreemac.doPhase(publicKey, true);

    //generate the shared key
    byte[] generatedkeybytes = keyAgreemac.generateSecret();

    //starts sea cipher can it only be DES?
    Cipher cipher = Cipher.getInstance(cProps.cache.getUser(clientId).getMacSpec());
    SecretKeyFactory skf = SecretKeyFactory.getInstance(cipher.getAlgorithm());
    KeySpec keySpec = new DESKeySpec(generatedkeybytes);
    SecretKey secretKey = skf.generateSecret(keySpec);

    // add keys to keystore
    KeyStore.SecretKeyEntry seaKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
    KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(cProps.keyStorePassword());
    cProps.ksHelper.getStore().setEntry(clientId + "-" + destinyuser + "-macshared", seaKeyEntry, protectionParam);
    cProps.ksHelper.getStore().store(new FileOutputStream(cProps.KEYSTORE_LOC), cProps.keyStorePassword());

    //init sea cipher
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    return cipher;

  }

  //TODO: Retirar daqui estes utils todos e meter na classe do crypt utils ou no cprops

  private static KeyAgreement createMACAgree(ClientProperties cProps) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException, BadPaddingException, IOException, InvalidAlgorithmParameterException, ClassNotFoundException {
    KeyAgreement keyAgree = KeyAgreement.getInstance(cProps.dhHelper.getAlgorithm());
    KeyPair myKeyPairforSEASpec = cProps.ksHelper.loadDHKeyPair("myusername", DHKeyType.MAC);
    keyAgree.init(myKeyPairforSEASpec.getPrivate());
    return keyAgree;
  }

  private static Cipher loadKeyAndInitHmacCipher(ClientProperties cProps, int clientId, int destinationId) throws PropertyException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchPaddingException, InvalidKeyException {
    Key k = cProps.ksHelper.getStore().getKey(clientId + "-" + destinationId + "-macshared", cProps.keyStorePassword());
    Cipher cipher = Cipher.getInstance(cProps.cache.getUser(clientId).getMacSpec());
    cipher.init(Cipher.ENCRYPT_MODE, k);
    return cipher;
  }

  private static Cipher loadKeyAndInitCipher(ClientProperties cProps, int clientId, int destinationId) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, PropertyException, NoSuchPaddingException, InvalidKeyException {
    Key k = cProps.ksHelper.getStore().getKey(clientId + "-" + destinationId + "-seashared", cProps.keyStorePassword());
    Cipher cipher = Cipher.getInstance(cProps.cache.getUser(clientId).getSeaSpec());
    cipher.init(Cipher.ENCRYPT_MODE, k);
    return cipher;
  }

  private static UserCacheEntry checkAndGetDestinyUser(ClientProperties cProps, int destinationId) throws IOException, ClientException {
    UserCacheEntry destinyuser;
    if (cProps.cache.getUser(destinationId) != null) {
      destinyuser = cProps.cache.getUser(destinationId);
    } else {
      JsonObject listrequestData = new JsonObject();
      listrequestData.addProperty("type", "list");
      listUsers(cProps, listrequestData, new String[]{String.valueOf(destinationId)});

      //user now added to cache
      destinyuser = cProps.cache.getUser(destinationId);
    }
    return destinyuser;
  }

  public static KeyAgreement createSEAAgree(ClientProperties cProps) throws NoSuchAlgorithmException, IOException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, InvalidKeySpecException, InvalidAlgorithmParameterException, ClassNotFoundException {
    KeyAgreement keyAgree = KeyAgreement.getInstance(cProps.dhHelper.getAlgorithm());
    KeyPair myKeyPairforSEASpec = cProps.ksHelper.loadDHKeyPair("myusername", DHKeyType.SEA);
    keyAgree.init(myKeyPairforSEASpec.getPrivate());
    return keyAgree;
  }

  public static Cipher generateSeaSharedKey(ClientProperties cProps, int clientId, KeyAgreement keyAgree, UserCacheEntry destinyuser) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, KeyStoreException, PropertyException, IOException, CertificateException {
    //add destiny user pub to agreement
    KeyFactory factory = KeyFactory.getInstance(cProps.dhHelper.getAlgorithm());
    X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(destinyuser.getDhSeaPubKey());
    PublicKey publicKey = factory.generatePublic(encodedKeySpec);
    keyAgree.doPhase(publicKey, true);

    //generate the shared key
    byte[] generatedkeybytes = keyAgree.generateSecret();

    //starts sea cipher can it only be DES?
    Cipher cipher = Cipher.getInstance(cProps.cache.getUser(clientId).getSeaSpec());
    SecretKeyFactory skf = SecretKeyFactory.getInstance(cipher.getAlgorithm());
    KeySpec keySpec = new DESKeySpec(generatedkeybytes);
    SecretKey secretKey = skf.generateSecret(keySpec);

    // add keys to keystore
    KeyStore.SecretKeyEntry seaKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
    KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(cProps.keyStorePassword());
    cProps.ksHelper.getStore().setEntry(clientId + "-" + destinyuser + "-seashared", seaKeyEntry, protectionParam);
    cProps.ksHelper.getStore().store(new FileOutputStream(cProps.KEYSTORE_LOC), cProps.keyStorePassword());

    //init sea cipher
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    return cipher;
  }

  private static void receiveMessages(ClientProperties cProps, JsonObject requestData, String[] args) throws IOException, ClientException {
    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));
    int messageid = Integer.parseInt(bf.readLine());
    requestData.addProperty("userId", messageid);
    cProps.sendRequest(requestData);

    ReceiveMessageResponse resp = cProps.receiveRequestWithNonce(requestData, ReceiveMessageResponse.class);

    Message m = resp.getMessage();
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

  private static void status(ClientProperties cProps, JsonObject requestData, String[] args) throws IOException, ClientException {
    BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));

    int messageid = Integer.parseInt(bf.readLine());
    requestData.addProperty("userId", messageid);
    cProps.sendRequest(requestData);

    MessageReceiptsResponse resp = cProps.receiveRequestWithNonce(requestData, MessageReceiptsResponse.class);

    /*
    System.out.println("Showing status for message: " + lmr.getMessage().getId());
    for (Receipt r : lmr.getReceipts()) {
      System.out.println("Date: " + r.getDate());
      System.out.println("Signature: " + r.getReceiverSignature());
    }
  */
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

  private static void printCommands() {
    System.out.println(
        "CREATE <username>" + "\n" +
            "LIST (userId)?" + "\n" +
            "NEW <messageBoxOwnerId>" + "\n" +
            "ALL <messageBoxOwnerId>" + "\n" +
            "SEND <destinationId> <messageText> (<attachmentFilePath>)*" + "\n" +
            "RECEIVE <messageId>" + "\n" +
            "STATUS <messageId>" + "\n" +
            "LOGIN <username" + "\n" +
            "HELP" + "\n" +
            "EXIT"
    );
  }

  /*
    UTILS
  */
  private static PublicKey verifyUserSecDataSignature(User user, ClientProperties cProps) throws ClientException {
    byte[] pubKeyDecoded;
    PublicKey userPublicKey;

    try {
      pubKeyDecoded = cProps.b64Helper.decode(user.getPubKey());
      userPublicKey = cProps.aeaHelper.pubKeyFromBytes(pubKeyDecoded);
    } catch (InvalidKeySpecException e) {
      throw new ClientException("User has a corrupted public key.");
    }

    try {
      boolean valid = cProps.aeaHelper.verifySignature(
          userPublicKey,
          Utils.joinByteArrays(
              cProps.b64Helper.decode(user.getDhSeaPubKey()),
              cProps.b64Helper.decode(user.getDhMacPubKey()),
              user.getSeaSpec().getBytes(),
              user.getMacSpec().getBytes()
          ),
          cProps.b64Helper.decode(user.getSecDataSignature())
      );

      if (!valid)
        throw new ClientException("User's signature does not match.");
    } catch (SignatureException | InvalidKeyException e) {
      throw new ClientException("Failed to verify user security data signature: " + e.getClass().getName() + ".");
    }

    return userPublicKey;
  }

  private static String getCurrentDate() {
    DateFormat df = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");

    return df.format(new Date());
  }

  private static SSLSocket createSocket(SSLSocketFactory sslSocketFactory, CustomProperties properties) throws PropertyException, IOException {
    int serverPort = properties.getInt(ClientProperty.SERVER_PORT);
    String serverAddress = properties.getString(ClientProperty.SERVER_ADDRESS);

    SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket(serverAddress, serverPort);
    socket.setSoTimeout(10 * 1000); // 10 seconds

    // Set enabled protocols and cipher suites and start SSL socket handshake with server
    socket.setEnabledProtocols(properties.getStringArr(ClientProperty.TLS_PROTOCOLS));
    socket.setEnabledCipherSuites(properties.getStringArr(ClientProperty.TLS_CIPHERSUITES));

    return socket;
  }
}
