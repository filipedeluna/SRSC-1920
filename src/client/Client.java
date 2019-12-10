package client;

import client.cache.UserCacheEntry;
import client.errors.ClientException;
import client.props.ClientProperty;
import client.utils.ClientRequest;
import client.utils.ValidFile;
import com.google.gson.JsonObject;
import shared.parameters.ServerParameterMap;
import shared.utils.Utils;
import shared.utils.crypto.MacHelper;
import shared.utils.crypto.SEAHelper;
import shared.utils.crypto.util.DHKeyType;
import shared.wrappers.Message;
import shared.wrappers.User;
import shared.errors.properties.PropertyException;
import shared.parameters.ServerParameter;
import shared.response.server.*;
import shared.utils.crypto.KSHelper;
import shared.utils.properties.CustomProperties;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DHParameterSpec;
import javax.net.ssl.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
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

      // Create SSL Socket and register Client properties
      SSLContext sslContext = buildSSLContext(ksHelper, tsHelper);
      SSLSocketFactory factory = sslContext.getSocketFactory();
      ClientProperties cProps = new ClientProperties(properties, ksHelper, tsHelper, factory);

      // Start handshake
      System.out.println("SSL setup finished.");
      System.out.println("Handshake completed.");

      cProps.startConnection();

      // Request shared parameters and that initialize dh and aea helpers
      requestParams(cProps);

      // Command reader
      BufferedReader lineReader = new BufferedReader(new InputStreamReader(System.in));

      // Close the socket
      cProps.closeConnection();

      while (true) {
        try {
          // Restart connection for new request with new socket and connect i/o
          cProps.startConnection();

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
              listUsers(cProps, requestData, cmdArgs, false);
              break;
            case NEW:
              listNewMessages(cProps, requestData, cmdArgs);
              break;
            case ALL:
              listAllMessages(cProps, requestData, cmdArgs);
              break;
            case SEND:
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

          cProps.closeConnection();
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

  private static void login(ClientProperties cProps, JsonObject requestData, String[] args) throws ClientException, IOException, GeneralSecurityException {
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
        username,
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

    cProps.establishSession(session); // TODO LOOKEI HERE

    System.out.println("User " + username + " successfully logged in.");
  }

  // TODO OOOOOOOOOOOOOOOOO VERIFY THE NONCES EVERYWHERE

  private static void requestParams(ClientProperties cProps) throws GeneralSecurityException, IOException, ClientException {
    JsonObject requestData = new JsonObject();

    // Create request parameters and send request
    requestData.addProperty("type", "params");
    String nonce = cProps.rndHelper.getNonce();
    requestData.addProperty("nonce", nonce);
    cProps.sendRequest(requestData);

    // Get response and check nonce
    ParametersResponse resp = cProps.receiveRequest(ParametersResponse.class);

    // Create parameters map class from received JSON
    ServerParameterMap paramsMap = resp.getParameters();

    // Verify parameters signature
    byte[] signatureDecoded = cProps.b64Helper.decode(paramsMap.getParameter(ServerParameter.PARAM_SIG));
    byte[] paramsBytes = paramsMap.getAllParametersBytes();

    boolean sigValid = cProps.aeaHelper.verifySignature(cProps.getServerPublicKey(), paramsBytes, signatureDecoded);

    if (!sigValid)
      throw new ClientException("The server parameters signature is not valid.");

    // Initialize AEA and DH Helper with the server parameters
    try {
      cProps.loadServerParams(paramsMap);
    } catch (Exception e) {
      throw new ClientException("The server parameters received are corrupted.");
    }
  }

  private static void createUser(ClientProperties cProps, JsonObject requestData, String[] args) throws IOException, GeneralSecurityException, ClientException {
    // Generate a uuid from a users chosen username, adding entropy to it
    String username = args[1].trim();
    String uuid = cProps.generateUUID(username);

    requestData.addProperty("uuid", uuid);

    // Generate Parameter Spec and create dh keypairs for mac and sea
    DHParameterSpec dhSpec = new DHParameterSpec(cProps.dhHelper.getP(), cProps.dhHelper.getG());
    KeyPair dhSeaKeypair = cProps.dhHelper.generateKeyPair(dhSpec);
    KeyPair dhMacKeypair = cProps.dhHelper.generateKeyPair(dhSpec);

    // Check user keys exist
    if (cProps.ksHelper.dhKeyPairExists(username, DHKeyType.SEA))
      throw new ClientException("User sea key already exists.");

    if (cProps.ksHelper.dhKeyPairExists(username, DHKeyType.MAC))
      throw new ClientException("User mac key already exists.");

    // Keys do not exist so save them to file
    cProps.ksHelper.saveDHKeyPair(username, DHKeyType.SEA, dhSeaKeypair);
    cProps.ksHelper.saveDHKeyPair(username, DHKeyType.MAC, dhMacKeypair);

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

  private static void listUsers(ClientProperties cProps, JsonObject requestData, String[] args, boolean silent) throws IOException, ClientException {
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

    // Print results
    if (!silent) {
      if (obtained.size() > 0)
        System.out.println("Obtained and verified user's with ids " + obtained.toString() + " info.");

      if (failed.size() > 0)
        System.err.println("Failed to verify user's with ids " + failed.toString() + " info.");

      if (obtained.size() == 0 && failed.size() == 0)
        System.err.println("No users found.");
    }
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
    // Get client and destination id
    int clientId = cProps.session.getId();
    int destinationId = Integer.parseInt(args[1]);
    requestData.addProperty("senderId", cProps.session.getId());
    requestData.addProperty("receiverId", Integer.parseInt(args[1]));

    // Validate message parameters
    String message = args[2];
    String fileSpec = "";
    ArrayList<ValidFile> validFiles = null;

    // Get files to send
    if (args.length > 3) {
      validFiles = cProps.fileHelper.getFiles(Arrays.copyOfRange(args, 3, args.length));
      fileSpec = cProps.fileHelper.getFileSpec(validFiles);
    }

    // Check user is logged in (in session and cache)
    UserCacheEntry client = cProps.cache.getUser(clientId);
    if (client == null)
      throw new ClientException("User is not logged in.");

    UserCacheEntry destinationUser = cProps.cache.getUser(destinationId);

    // If user is not in cache, we will have to request the server to get him
    if (destinationUser == null) {
      System.out.println("User not found in cache. fetching from server...");
      // We'll start by building the request
      JsonObject requestDataToGetUser = new JsonObject();
      requestDataToGetUser.addProperty("type", "list");
      requestDataToGetUser.addProperty("nonce", cProps.rndHelper.getNonce());

      // Create "fake" args and do request, user will be added to cache
      String[] fakeArgs = new String[]{"", String.valueOf(destinationId)};
      listUsers(cProps, requestDataToGetUser, fakeArgs, true);

      // Restart socket connection
      cProps.closeConnection();
      cProps.startConnection();

      // TODO AGGRESSIVE MODEEEEE??? - get all users instead of just this one every time we miss one?????
      // Check if user is now in cache
      destinationUser = cProps.cache.getUser(destinationId);

      // If user not in cache either he doesn't exist or we couldn't get him
      if (destinationUser == null)
        throw new ClientException("Couldn't get user from server.");
    }

    // Get shared keys
    Key sharedSeaKey = cProps.ksHelper.getSharedKey(clientId, destinationId, DHKeyType.SEA, cProps.keyStorePassword());
    Key sharedMacKey = cProps.ksHelper.getSharedKey(clientId, destinationId, DHKeyType.MAC, cProps.keyStorePassword());

    // If shared keys don't exist, generate them
    if (sharedSeaKey == null || sharedMacKey == null) {
      cProps.generateDHSharedKeys(destinationId);

      // Get them again
      sharedSeaKey = cProps.ksHelper.getSharedKey(clientId, destinationId, DHKeyType.SEA, cProps.keyStorePassword());
      sharedMacKey = cProps.ksHelper.getSharedKey(clientId, destinationId, DHKeyType.MAC, cProps.keyStorePassword());
    }

    // Get client ciphers from the current session
    MacHelper macHelper = cProps.session.macHelper;
    SEAHelper seaHelper = cProps.session.seaHelper;

    // Start encrypting message contents
    byte[] tempCipherIVBytes;
    byte[] cipherIVBytes = new byte[0];
    byte[] encryptedMessageBytes;
    byte[] encryptedFileSpecBytes = new byte[0];
    byte[] encryptedFilesBytes = new byte[0];

    // Encrypt and add message text
    // We will use 3 different IVs due to possible vulnerabilities with certain ciphers/modes (GCM)
    if (seaHelper.cipherModeUsesIV()) {
      tempCipherIVBytes = seaHelper.generateIV();
      cipherIVBytes = Utils.joinByteArrays(cipherIVBytes, tempCipherIVBytes);

      encryptedMessageBytes = seaHelper.encrypt(message.getBytes(StandardCharsets.UTF_8), sharedSeaKey, tempCipherIVBytes);
    } else {
      encryptedMessageBytes = seaHelper.encrypt(message.getBytes(StandardCharsets.UTF_8), sharedSeaKey);
    }
    requestData.addProperty("text", cProps.b64Helper.encode(encryptedMessageBytes));

    // Encrypt and add file info
    if (!fileSpec.equals("")) {
      if (seaHelper.cipherModeUsesIV()) {
        tempCipherIVBytes = seaHelper.generateIV();
        cipherIVBytes = Utils.joinByteArrays(cipherIVBytes, tempCipherIVBytes);

        encryptedFileSpecBytes = seaHelper.encrypt(fileSpec.getBytes(StandardCharsets.UTF_8), sharedSeaKey, tempCipherIVBytes);
      } else
        encryptedFileSpecBytes = seaHelper.encrypt(fileSpec.getBytes(StandardCharsets.UTF_8), sharedSeaKey);
      requestData.addProperty("attachmentData", cProps.b64Helper.encode(encryptedFileSpecBytes));
    } else
      requestData.addProperty("attachmentData", "");

    // Encrypt and add all files bytes
    if (validFiles != null) {
      byte[] filesBytes = cProps.fileHelper.readAllFiles(validFiles);

      if (seaHelper.cipherModeUsesIV()) {
        tempCipherIVBytes = seaHelper.generateIV();
        cipherIVBytes = Utils.joinByteArrays(cipherIVBytes, tempCipherIVBytes);

        encryptedFilesBytes = seaHelper.encrypt(filesBytes, sharedSeaKey, tempCipherIVBytes);
      } else
        encryptedFilesBytes = seaHelper.encrypt(filesBytes, sharedSeaKey);
      requestData.addProperty("attachments", cProps.b64Helper.encode(encryptedFilesBytes));
    } else
      requestData.addProperty("attachments", "");


    // Add Cipher IVs to request
    if (cipherIVBytes.length != 0)
      requestData.addProperty("cipherIV", cProps.b64Helper.encode(cipherIVBytes));
    else
      requestData.addProperty("cipherIV", "");

    // Join all data for user mac signature and add it to the request
    byte[] messageData = Utils.joinByteArrays(
        encryptedMessageBytes,
        encryptedFileSpecBytes,
        encryptedFilesBytes,
        cipherIVBytes
    );

    byte[] authenticatedMessageData = macHelper.macHash(messageData, sharedMacKey);
    requestData.addProperty("senderSignature", cProps.b64Helper.encode(authenticatedMessageData));

    // Send request
    cProps.sendRequest(requestData);

    SendMessageResponse resp = cProps.receiveRequestWithNonce(requestData, SendMessageResponse.class);

    System.out.println("Successfully sent message to user " + destinationId + " with id " + resp.getMessageId());
  }

  private static Cipher generateMACSharedKey(ClientProperties cProps, int clientId, KeyAgreement
      keyAgreemac, UserCacheEntry destinyuser) throws
      NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, PropertyException, KeyStoreException, IOException, CertificateException {
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


  private static void receiveMessages(ClientProperties cProps, JsonObject requestData, String[] args) throws
      IOException, ClientException {
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

  private static void status(ClientProperties cProps, JsonObject requestData, String[] args) throws
      IOException, ClientException {
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

  private static KSHelper getKeyStore(CustomProperties properties) throws
      PropertyException, GeneralSecurityException, IOException {
    String keyStoreLoc = properties.getString(ClientProperty.KEYSTORE_LOC);
    String keyStorePass = properties.getString(ClientProperty.KEYSTORE_PASS);
    String keyStoreType = properties.getString(ClientProperty.KEYSTORE_TYPE);

    return new KSHelper(keyStoreLoc, keyStoreType, keyStorePass.toCharArray(), false);
  }

  private static KSHelper getTrustStore(CustomProperties properties) throws
      PropertyException, IOException, GeneralSecurityException {
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


}
