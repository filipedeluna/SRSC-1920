package client;

import client.cache.MessageCacheEntry;
import client.cache.UserCacheEntry;
import client.errors.ClientException;
import client.props.ClientProperty;
import client.utils.ClientRequest;
import client.utils.ValidFile;
import com.google.gson.JsonObject;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import shared.Pair;
import shared.errors.properties.PropertyException;
import shared.parameters.ServerParameter;
import shared.parameters.ServerParameterMap;
import shared.response.pki.SignResponse;
import shared.response.server.*;
import shared.utils.Utils;
import shared.utils.crypto.*;
import shared.utils.crypto.util.DHKeyType;
import shared.utils.properties.CustomProperties;
import shared.wrappers.Message;
import shared.wrappers.Receipt;
import shared.wrappers.User;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DHParameterSpec;
import javax.net.ssl.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

class Client {
  private static final String PROPS_PATH = "src/client/props/client.properties";
  private static final boolean DEBUG_MODE = true;

  public static void main(String[] args) {
    System.setProperty("javax.net.debug", DEBUG_MODE ? "true" : "false");
    System.setProperty("java.net.preferIPv4Stack", "true");

    // Get properties from file
    CustomProperties properties = null;
    boolean debug = false;
    try {
      properties = new CustomProperties(PROPS_PATH);
      debug = properties.getBool(ClientProperty.DEBUG);
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

      // Connect to PKI to obtain cert
      if (properties.getBool(ClientProperty.USE_PKI)) {
        cProps.startConnection(true);
        connectToPki(cProps);
        System.exit(0);
      }

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
              listNewMessages(cProps, requestData);
              break;
            case ALL:
              listAllMessages(cProps, requestData);
              break;
            case SEND:
              sendMessages(cProps, requestData, cmdArgs);
              break;
            case RECV:
              receiveMessage(cProps, requestData, cmdArgs);
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
          if (debug)
            e.printStackTrace();
        } catch (ClassCastException e) {
          System.err.println("Received an invalid format message.");
        }
      }
    } catch (Exception e) {
      System.err.println("CRITICAL ERROR: " + e.getMessage());
      if (debug)
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

    cProps.establishSession(session);

    System.out.println("User " + username + " successfully logged in.");
  }

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

    try {
      cProps.loadServerParams(paramsMap);
    } catch (Exception e) {
      throw new ClientException("The server parameters received are corrupted.");
    }

    boolean sigValid = cProps.aeaHelper.verifySignature(cProps.getServerPublicKey(), paramsBytes, signatureDecoded);

    if (!sigValid)
      throw new ClientException("The server parameters signature is not valid.");
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
    // Check user logged in and add his id to request and send it
    if (cProps.session == null)
      throw new ClientException("User is not logged in.");
    requestData.addProperty("userId", cProps.session.getId());

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

  private static void listNewMessages(ClientProperties cProps, JsonObject requestData) throws IOException, ClientException {
    // Check user logged in and add his id to request and send it
    if (cProps.session == null)
      throw new ClientException("User is not logged in.");
    requestData.addProperty("userId", cProps.session.getId());

    cProps.sendRequest(requestData);

    // Get response and check the nonce
    ListNewMessagesResponse resp = cProps.receiveRequestWithNonce(requestData, ListNewMessagesResponse.class);

    // Get new message ids an print them
    System.out.println("Obtained the following unread message ids: (" + resp.getNewMessageIds().toString() + ").");
  }

  private static void listAllMessages(ClientProperties cProps, JsonObject requestData) throws IOException, ClientException {
    // Check user logged in and add his id to request and send it
    if (cProps.session == null)
      throw new ClientException("User is not logged in.");
    requestData.addProperty("userId", cProps.session.getId());

    cProps.sendRequest(requestData);

    // Get response and check the nonce
    ListMessagesResponse resp = cProps.receiveRequestWithNonce(requestData, ListMessagesResponse.class);

    // Get new message ids an print them
    System.out.println("Obtained the following received message ids: (" + resp.getReceivedMessageIds().toString() + ").");
    System.out.println("Obtained the following sent message ids: (" + resp.getSentMessageIds().toString() + ").");
    System.out.println("Note: Read messages come with a prefixed \"_\".");
  }

  private static void sendMessages(ClientProperties cProps, JsonObject requestData, String[] args) throws IOException, GeneralSecurityException, ClientException, PropertyException {
    // Check user is logged in (in session and cache)
    if (cProps.session == null)
      throw new ClientException("User is not logged in.");

    // Get client and destination id
    int destinationId = Integer.parseInt(args[1]);
    requestData.addProperty("senderId", cProps.session.getId());
    requestData.addProperty("receiverId", Integer.parseInt(args[1]));

    // Validate message parameters
    String message = args[2];
    String fileSpec = "";
    ArrayList<ValidFile> validFiles = null;

    try {
      // Get files to send
      if (args.length > 3) {
        validFiles = cProps.fileHelper.getFiles(Arrays.copyOfRange(args, 3, args.length));
        fileSpec = cProps.fileHelper.getFileSpec(validFiles);
      }
    } catch (IOException e) {
      throw new ClientException("Failed to get files for attachment.");
    }

    // Check user already exists in cache. Fetch him otherwise
    Pair<Pair<SEAHelper, MacHelper>, Pair<Key, Key>> sharedParameters = getUsersParameters(cProps, destinationId);

    // Create ciphers with other users params
    SEAHelper seaHelper = cProps.session.seaHelper;
    MacHelper macHelper = cProps.session.macHelper;

    // Get shared key pairs
    Key sharedSeaKey = sharedParameters.getB().getA();
    Key sharedMacKey = sharedParameters.getB().getB();

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

    byte[] authenticatedMessageData = macHelper.hash(messageData, sharedMacKey);
    requestData.addProperty("senderSignature", cProps.b64Helper.encode(authenticatedMessageData));

    // Send request
    cProps.sendRequest(requestData);

    SendMessageResponse resp = cProps.receiveRequestWithNonce(requestData, SendMessageResponse.class);

    // Add message to cache
    cProps.cache.addMessage(
        resp.getMessageId(),
        new

            MessageCacheEntry(
            cProps.session.getId(),

            destinationId,
            encryptedMessageBytes,
            encryptedFileSpecBytes,
            encryptedFilesBytes,
            cipherIVBytes
        )
    );

    System.out.println("Successfully sent message to user " + destinationId + " with id " + resp.getMessageId());
  }

  private static void receiveMessage(ClientProperties cProps, JsonObject requestData, String[] args) throws IOException, ClientException, GeneralSecurityException, PropertyException {
    // Check user is logged in (in session and cache)
    if (cProps.session == null)
      throw new ClientException("User is not logged in.");

    // Get message id and check if it is in cache
    int messageId = Integer.parseInt(args[1]);
    MessageCacheEntry messageCacheEntry = cProps.cache.getMessage(messageId);

    int senderId;
    int receiverId;
    Message message = null;

    if (messageCacheEntry == null) {
      // Get message object from the server response
      requestData.addProperty("messageId", messageId);
      cProps.sendRequest(requestData);
      ReceiveMessageResponse resp = cProps.receiveRequestWithNonce(requestData, ReceiveMessageResponse.class);
      message = resp.getMessage();

      // Get message sender
      senderId = message.getSenderId();
      receiverId = message.getReceiverId();
    } else {
      senderId = messageCacheEntry.getSenderId();
      receiverId = messageCacheEntry.getReceiverId();
    }

    if (receiverId != cProps.session.getId())
      throw new ClientException("Message is not intended for user.");

    // Check user already exists in cache. Fetch him otherwise
    Pair<Pair<SEAHelper, MacHelper>, Pair<Key, Key>> sharedParameters = getUsersParameters(cProps, senderId);

    // Create ciphers with other users params
    SEAHelper seaHelper = sharedParameters.getA().getA();
    MacHelper macHelper = sharedParameters.getA().getB();

    // Get shared key pairs
    Key sharedSeaKey = sharedParameters.getB().getA();
    Key sharedMacKey = sharedParameters.getB().getB();

    // Validate message contents by verifying mac
    byte[] encryptedText;
    byte[] encryptedFileSpec;
    byte[] encryptedFiles;
    byte[] iv;
    byte[] signature;

    if (messageCacheEntry == null) {
      System.out.println("Message not found in cache. Fetching...");

      encryptedText = cProps.b64Helper.decode(message.getText());
      encryptedFileSpec = cProps.b64Helper.decode(message.getAttachmentData());
      encryptedFiles = cProps.b64Helper.decode(message.getAttachments());
      iv = cProps.b64Helper.decode(message.getIV());
      signature = cProps.b64Helper.decode(message.getSenderSignature());

      byte[] contents = Utils.joinByteArrays(
          encryptedText,
          encryptedFileSpec,
          encryptedFiles,
          iv
      );

      if (!macHelper.verifyHash(contents, signature, sharedMacKey))
        throw new ClientException("Message has an invalid signature");
    } else {
      encryptedText = messageCacheEntry.getText();
      encryptedFileSpec = messageCacheEntry.getAttachmentData();
      encryptedFiles = messageCacheEntry.getAttachments();
      iv = messageCacheEntry.getCipherIV();
    }

    // Validate the iv and decrypt message parts
    int ivCount = validateMessageIv(encryptedFileSpec, encryptedFiles, iv, seaHelper);

    String text;
    String fileSpec = null;
    byte[] decryptedFiles = new byte[0];
    try {
      text = decryptMessageText(encryptedText, sharedSeaKey, iv, seaHelper);

      // We can use the IV count to deduce if there are attachments
      if (ivCount > 1) {
        fileSpec = decryptMessageFileSpec(encryptedFileSpec, sharedSeaKey, iv, seaHelper);
        decryptedFiles = decryptMessageFiles(encryptedFiles, sharedSeaKey, iv, seaHelper);
      }
    } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
      throw new ClientException("Sea key is invalid or corrupted.");
    }

    // Parse filespec to start writing files
    if (ivCount > 1) {
      ArrayList<Pair<String, Integer>> fileSpecPairs = cProps.fileHelper.parseFileSpec(fileSpec);

      byte[] fileBytes;
      if (!fileSpecPairs.isEmpty() && decryptedFiles.length == 0)
        throw new ClientException("Message attachments are corrupted.");

      // Write decrypted files to system
      for (Pair<String, Integer> fileSpecPair : fileSpecPairs) {
        try {
          fileBytes = Arrays.copyOfRange(decryptedFiles, 0, fileSpecPair.getB());
          decryptedFiles = Arrays.copyOfRange(decryptedFiles, fileBytes.length, decryptedFiles.length);

          cProps.fileHelper.writeFile(fileSpecPair.getA(), fileBytes);

          System.out.println("Wrote file: " + fileSpecPair.getA());
        } catch (IOException e) {
          System.err.println("Failed to write file: " + fileSpecPair.getA());
        }
      }
    }

    // Add message to cache
    if (messageCacheEntry == null) {
      cProps.cache.addMessage(
          message.getId(),
          new MessageCacheEntry(
              message.getSenderId(),
              message.getReceiverId(),
              encryptedText,
              encryptedFileSpec,
              encryptedFiles,
              iv
          )
      );
    }

    System.out.println("Message text: " + text);
    System.out.println("Successfully received message with id: " + messageId);

    // Prepare to send receipt by resetting connection and building header
    cProps.startConnection();

    requestData.addProperty("type", "receipt");
    requestData.addProperty("messageId", messageId);
    requestData.addProperty("senderId", cProps.session.getId());

    // Get current date
    String currentDate = getCurrentDate();

    // Sign decrypted data with mac and add to request
    byte[] decryptedContents;
    if (ivCount > 1) {
      decryptedContents = Utils.joinByteArrays(
          text.getBytes(StandardCharsets.UTF_8),
          fileSpec.getBytes(StandardCharsets.UTF_8),
          decryptedFiles,
          currentDate.getBytes(StandardCharsets.UTF_8)
      );
    } else {
      decryptedContents = Utils.joinByteArrays(
          text.getBytes(StandardCharsets.UTF_8),
          currentDate.getBytes(StandardCharsets.UTF_8)
      );
    }

    byte[] signedDecryptedContents = macHelper.hash(decryptedContents, sharedMacKey);

    // Add signature and date to request header and send the request
    requestData.addProperty("receiverSignature", cProps.b64Helper.encode(signedDecryptedContents));
    requestData.addProperty("date", currentDate);

    cProps.sendRequest(requestData);

    System.out.println("Successfully sent receipt of message with id: " + messageId);
  }

  private static void status(ClientProperties cProps, JsonObject requestData, String[] args) throws IOException, ClientException, NoSuchAlgorithmException, PropertyException, InvalidKeyException {
    // Check user is logged in (in session and cache)
    if (cProps.session == null)
      throw new ClientException("User is not logged in.");

    // Send message id to obtain response
    int messageId = Integer.parseInt(args[1]);
    requestData.addProperty("messageId", messageId);
    cProps.sendRequest(requestData);

    // Get response object and extract messages and receipts
    MessageReceiptsResponse resp = cProps.receiveRequestWithNonce(requestData, MessageReceiptsResponse.class);
    ArrayList<Receipt> receipts = resp.getReceipts();
    Message message = resp.getMessage();

    // Check session user is message sender
    if (message.getSenderId() != cProps.session.getId())
      throw new ClientException("Message was not sent by user. Can't verify receipts.");

    // Check user already exists in cache. Fetch him otherwise
    Pair<Pair<SEAHelper, MacHelper>, Pair<Key, Key>> sharedParameters = getUsersParameters(cProps, message.getReceiverId());

    // Create ciphers with other users params
    SEAHelper seaHelper = sharedParameters.getA().getA();
    MacHelper macHelper = sharedParameters.getA().getB();

    // Get shared key pairs
    Key sharedSeaKey = sharedParameters.getB().getA();
    Key sharedMacKey = sharedParameters.getB().getB();

    // Validate message contents by verifying mac, check if it has been tampered with
    byte[] encryptedText = cProps.b64Helper.decode(message.getText());
    byte[] encryptedFileSpec = cProps.b64Helper.decode(message.getAttachmentData());
    byte[] encryptedFiles = cProps.b64Helper.decode(message.getAttachments());
    byte[] iv = cProps.b64Helper.decode(message.getIV());
    byte[] signature = cProps.b64Helper.decode(message.getSenderSignature());

    byte[] contents = Utils.joinByteArrays(
        encryptedText,
        encryptedFileSpec,
        encryptedFiles,
        iv
    );

    if (!macHelper.verifyHash(contents, signature, sharedMacKey))
      throw new ClientException("Message has an invalid signature. It has been tampered with.");

    // Validate the iv and decrypt message parts
    int ivCount = validateMessageIv(encryptedFileSpec, encryptedFiles, iv, seaHelper);

    String text;
    String fileSpec = null;
    byte[] decryptedFiles = new byte[0];
    try {
      text = decryptMessageText(encryptedText, sharedSeaKey, iv, seaHelper);

      if (ivCount > 1) {
        fileSpec = decryptMessageFileSpec(encryptedFileSpec, sharedSeaKey, iv, seaHelper);
        decryptedFiles = decryptMessageFiles(encryptedFiles, sharedSeaKey, iv, seaHelper);
      }
    } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
      throw new ClientException("Sea key is invalid or corrupted.");
    }

    // Get decryptedData macHash
    byte[] decryptedContents;

    if (ivCount > 1) {
      decryptedContents = Utils.joinByteArrays(
          text.getBytes(StandardCharsets.UTF_8),
          fileSpec.getBytes(StandardCharsets.UTF_8),
          decryptedFiles
      );
    } else
      decryptedContents = text.getBytes();

    // Check receipt validity 1 by 1
    byte[] verificationData;
    byte[] receiptSignature;

    ArrayList<Pair<String, String>> results = new ArrayList<>();
    for (Receipt receipt : receipts) {
      // Check user already exists in cache. Fetch him otherwise
      sharedParameters = getUsersParameters(cProps, receipt.getSenderId());

      // Create ciphers with other users params
      macHelper = sharedParameters.getA().getB();

      // Get shared key pairs
      sharedMacKey = sharedParameters.getB().getB();

      verificationData = Utils.joinByteArrays(
          decryptedContents,
          receipt.getDate().getBytes(StandardCharsets.UTF_8)
      );

      // Try to decode signature
      try {
        receiptSignature = cProps.b64Helper.decode(receipt.getReceiverSignature());
      } catch (IllegalArgumentException e) {
        receiptSignature = new byte[0];
      }

      // Verify signature
      if (macHelper.verifyHash(verificationData, receiptSignature, sharedMacKey))
        results.add(new Pair<>("valid", "user id: " + receipt.getSenderId() + "date: " + receipt.getDate()));
      else
        results.add(new Pair<>("invalid/Forged", "user id: " + receipt.getSenderId() + " date: " + receipt.getDate()));
    }

    // Print results
    for (Pair<String, String> resultPair : results) {
      System.out.println("Message status: " + resultPair.getA() + " - " + resultPair.getB() + ".");
    }
  }

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

  // This method lets the user register in the PKI
  private static void connectToPki(ClientProperties cProps) throws GeneralSecurityException, PropertyException, IOException, ClientException {
    // Get pub key name and size properties
    Pair<Integer, String> keyNameAndSize = cProps.getPubKeyNameAndSize();

    // Build specific pki AEA helper for key and cert manipulation
    AEAHelper aeaHelper = cProps.getPKIAEAHelper();

    // Generate keypair and certificate from it
    KeyPair keyPair = aeaHelper.genKeyPair(keyNameAndSize.getA());
    PKCS10CertificationRequest csr = aeaHelper.generateCSR(keyNameAndSize.getB(), keyPair);

    // Start building request to sign user key pair
    JsonObject requestData = new JsonObject();
    B64Helper b64Helper = new B64Helper();

    requestData.addProperty("type", "sign");
    requestData.addProperty("token", cProps.getPKIToken());
    requestData.addProperty("certificationRequest", b64Helper.encode(csr.getEncoded()));

    // Send request and obtain response
    cProps.sendRequest(requestData);

    SignResponse resp = cProps.receiveRequest(SignResponse.class);

    // Get certificate and save it in the keystore
    String certificateEncoded = resp.getCertificate();
    byte[] certBytes = b64Helper.decode(certificateEncoded);

    // Create key entry with attached generated chain
    X509Certificate cert = aeaHelper.getCertFromBytes(certBytes);
    cProps.saveKeyPair(keyPair, new X509Certificate[]{cert});

    System.out.println("Keypair successfully generated and signed by the pki.");
  }

  /*
    UTILS
  */
  private static String getCurrentDate() {
    DateFormat df = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");

    return df.format(new Date());
  }

  private static UserCacheEntry fetchUser(ClientProperties cProps, int userId) throws IOException, ClientException {
    System.out.println("User not found in cache. fetching from server...");
    // We'll start by building the request
    JsonObject requestDataToGetUser = new JsonObject();
    requestDataToGetUser.addProperty("type", "list");
    requestDataToGetUser.addProperty("nonce", cProps.rndHelper.getNonce());

    // Restart socket connection
    cProps.startConnection();

    // Create "fake" args and do request, user will be added to cache
    String[] fakeArgs = new String[]{"", String.valueOf(userId)};
    listUsers(cProps, requestDataToGetUser, fakeArgs, true);

    // Restart socket connection
    cProps.startConnection();

    // TODO AGGRESSIVE MODEEEEE??? - get all users instead of just this one every time we miss one?????
    return cProps.cache.getUser(userId);
  }

  private static String decryptMessageText(byte[] encryptedText, Key key, byte[] iv, SEAHelper seaHelper) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
    byte[] decryptedText;

    if (seaHelper.cipherModeUsesIV())
      decryptedText = seaHelper.decrypt(encryptedText, key, Arrays.copyOfRange(iv, 0, iv.length));
    else
      decryptedText = seaHelper.decrypt(encryptedText, key);

    return new String(decryptedText, StandardCharsets.UTF_8);
  }

  private static String decryptMessageFileSpec(byte[] encryptedFileSpec, Key key, byte[] iv, SEAHelper seaHelper) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
    byte[] decryptedFileSpec;
    if (seaHelper.cipherModeUsesIV())
      decryptedFileSpec = seaHelper.decrypt(encryptedFileSpec, key, Arrays.copyOfRange(iv, iv.length, iv.length * 2));
    else
      decryptedFileSpec = seaHelper.decrypt(encryptedFileSpec, key);

    return new String(decryptedFileSpec, StandardCharsets.UTF_8);
  }

  private static byte[] decryptMessageFiles(byte[] encryptedFiles, Key key, byte[] iv, SEAHelper seaHelper) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
    byte[] decryptedFiles;
    if (seaHelper.cipherModeUsesIV())
      decryptedFiles = seaHelper.decrypt(encryptedFiles, key, Arrays.copyOfRange(iv, iv.length * 2, iv.length * 3));
    else
      decryptedFiles = seaHelper.decrypt(encryptedFiles, key);

    return decryptedFiles;
  }

  private static Pair<SEAHelper, MacHelper> getSharedHelpers(String seaSpec, String macSpec) throws ClientException {
    try {
      MacHelper macHelper = new MacHelper(macSpec);

      if ( seaSpec.split("/").length != 3)
        throw new ClientException("User has an invalid key spec.");

      SEAHelper seaHelper = new SEAHelper(seaSpec);

      return new Pair<>(seaHelper, macHelper);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
      throw new ClientException("User has an invalid key spec.");
    }
  }

  private static Pair<Pair<SEAHelper, MacHelper>, Pair<Key, Key>> getUsersParameters(ClientProperties cProps, int otherId) throws IOException, ClientException, NoSuchAlgorithmException, PropertyException {
    // Check user already exists in cache. Fetch him otherwise
    UserCacheEntry otherUser = cProps.cache.getUser(otherId);

    if (otherUser == null)
      otherUser = fetchUser(cProps, otherId);

    if (otherUser == null)
      throw new ClientException("Failed to fetch receipt sender from server.");

    // Create ciphers with other users params
    Pair<SEAHelper, MacHelper> sharedHelpers = getSharedHelpers(otherUser.getSeaSpec(), otherUser.getMacSpec());

    // Get shared key pairs
    Pair<Key, Key> sharedKeys = cProps.getSharedKeys(otherId);

    return new Pair<>(sharedHelpers, sharedKeys);
  }

  private static int validateMessageIv(byte[] encryptedFileSpec, byte[] encryptedFiles, byte[] iv, SEAHelper seaHelper) throws ClientException {
    // Verify if message has files or file spec to determine integrity and iv size
    if (encryptedFileSpec.length != 0 && encryptedFiles.length == 0)
      throw new ClientException("Message files are corrupted");

    if (encryptedFileSpec.length == 0 && encryptedFiles.length != 0)
      throw new ClientException("Message file spec is corrupted");

    int ivCount = encryptedFiles.length > 0 ? 3 : 1;

    // Decrypt message parts
    if (seaHelper.cipherModeUsesIV() && iv.length != ivCount * seaHelper.ivSize())
      throw new ClientException("Message iv is corrupted");

    return ivCount;
  }
}
