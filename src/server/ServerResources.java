package server;

import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import server.db.wrapper.Message;
import server.db.wrapper.Receipt;
import server.response.*;
import server.db.ServerParameterMap;
import server.db.wrapper.User;
import shared.Pair;
import shared.ServerRequest;
import shared.errors.IHTTPStatusException;
import shared.errors.db.CriticalDatabaseException;
import shared.errors.db.DatabaseException;
import shared.errors.request.InvalidFormatException;
import shared.errors.request.InvalidRouteException;
import shared.errors.request.MissingValueException;
import shared.errors.request.RequestException;
import shared.http.HTTPStatus;
import shared.response.EchoResponse;
import shared.response.ErrorResponse;
import shared.utils.GsonUtils;
import shared.utils.SafeInputStreamReader;

import javax.net.ssl.SSLSocket;
import java.security.*;
import java.security.cert.X509Certificate;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;

class ServerResources implements Runnable {
  private SSLSocket client;
  private JsonReader input;
  private OutputStream output;

  private ServerProperties props;

  ServerResources(SSLSocket client, ServerProperties props) {
    this.client = client;
    this.props = props;

    try {
      input = new JsonReader(new SafeInputStreamReader(client.getInputStream()));
      output = client.getOutputStream();
    } catch (Exception e) {
      handleException(e);
      Thread.currentThread().interrupt();
    }
  }

  public void run() {
    try {
      JsonObject parsedRequest = parseRequest(input);

      handleRequest(parsedRequest);

      client.close();
    } catch (Exception e) {
      handleException(e);
    }
  }

  private void handleRequest(JsonObject requestData) throws RequestException, IOException, DatabaseException, GeneralSecurityException, CriticalDatabaseException {
    try {
      String requestName = GsonUtils.getString(requestData, "type");
      ServerRequest request = ServerRequest.fromString(requestName);
      String nonce = null;

      // Check route is valid
      if (request == null)
        throw new InvalidRouteException();

      // Get nonce if supposed to for the requested route
      if (request.needsNonce())
        nonce = GsonUtils.getString(requestData, "nonce");

      switch (request) {
        case ECHO:
          echo(requestData);
          break;
        case CREATE:
          createUser(requestData, nonce);
          break;
        case LIST:
          listUsers(requestData, nonce);
          break;
        case NEW:
          listNewMessages(requestData, nonce);
          break;
        case ALL:
          listMessages(requestData, nonce);
          break;
        case SEND:
          sendMessage(requestData, nonce);
          break;
        case RECEIVE:
          receiveMessage(requestData, nonce);
          break;
        case RECEIPT:
          sendMessageReceipt(requestData);
          break;
        case STATUS:
          getMessageStatus(requestData, nonce);
          break;
        case PARAMS:
          params(nonce);
          break;
      }
    } catch (ClassCastException | IllegalStateException e) {
      throw new InvalidRouteException();
    }
  }

  // Echo
  private void echo(JsonObject requestData) throws RequestException, IOException {
    String message = GsonUtils.getString(requestData, "message");

    EchoResponse response = new EchoResponse(message);

    send(response.json(props.GSON));
  }

  // Create user message box
  private synchronized void createUser(JsonObject requestData, String nonce) throws RequestException, IOException, DatabaseException, CriticalDatabaseException {
    // Get public key and certificate from user
    X509Certificate certificate = (X509Certificate) client.getSession().getPeerCertificates()[0];
    PublicKey publicKey = certificate.getPublicKey();
    String publicKeyEncoded = props.B64.encode(publicKey.getEncoded());

    // Get user intended uuid and message verification nonce
    String uuid = GsonUtils.getString(requestData, "uuid");

    // Get extra fields
    String dhValue = GsonUtils.getString(requestData, "dhValue");

    // Get extra fields signature
    String secDataSignature = GsonUtils.getString(requestData, "secDataSignature");

    User user = new User(
        uuid,
        publicKeyEncoded,
        dhValue,
        secDataSignature
    );

    int userId = props.DB.insertUser(user);

    CreateUserResponse response = new CreateUserResponse(nonce, userId);

    send(response.json(props.GSON));
  }

  // List users details
  private void listUsers(JsonObject requestData, String nonce) throws RequestException, IOException, CriticalDatabaseException {
    // Get intended user id or none if supposed to get all users
    int userId;

    try {
      userId = GsonUtils.getInt(requestData, "userId");
    } catch (MissingValueException e) {
      userId = -1;
    }

    ArrayList<User> users = new ArrayList<>();

    if (userId < 0)
      users.add(props.DB.getUser(userId));
    else
      users = props.DB.getAllUsers();

    String usersJSON = props.GSON.toJson(users);

    ListUsersResponse response = new ListUsersResponse(nonce, usersJSON);

    send(response.json(props.GSON));
  }

  // List new messages
  private synchronized void listNewMessages(JsonObject requestData, String nonce) throws RequestException, IOException, CriticalDatabaseException {
    // Get intended user id or none if supposed to get all users
    int userId = GsonUtils.getInt(requestData, "userId");

    // Get unread messages and crete response object
    ArrayList<Integer> newMessageIds = props.DB.getUnreadMessages(userId);
    ListNewMessagesResponse response = new ListNewMessagesResponse(nonce, newMessageIds);

    send(response.json(props.GSON));
  }

  // List all messages
  private synchronized void listMessages(JsonObject requestData, String nonce) throws RequestException, IOException, CriticalDatabaseException {
    // Get intended user id messages
    int userId = GsonUtils.getInt(requestData, "userId");

    // Get all messages, split between received/sent and create response object
    Pair<ArrayList<String>, ArrayList<Integer>> messages = props.DB.getAllMessages(userId);

    ArrayList<String> receivedMessageIds = messages.A;
    ArrayList<Integer> sentMessagesIds = messages.B;

    ListMessagesResponse response = new ListMessagesResponse(nonce, receivedMessageIds, sentMessagesIds);

    send(response.json(props.GSON));
  }

  // Is Revoked
  private synchronized void sendMessage(JsonObject requestData, String nonce) throws RequestException, IOException, CriticalDatabaseException {
    // Get sender and receiver ids
    int senderId = GsonUtils.getInt(requestData, "source");
    int receiverId = GsonUtils.getInt(requestData, "destination");

    // Get message (encrypted and encoded) parts and respective mac hash of them
    String text = GsonUtils.getString(requestData, "text");

    byte[] attachments = new byte[0];
    String attachmentData = "";

    // Check if attachment was sent
    try {
      attachmentData = GsonUtils.getString(requestData, "attachmentData");
      attachments = props.B64.decode(GsonUtils.getString(requestData, "attachments"));
    } catch (MissingValueException e) {
      // Message has no attachments
    }

    String macHash = GsonUtils.getString(requestData, "macHash");

    // Create and insert message
    Message message = new Message(
        senderId,
        receiverId,
        text,
        attachmentData,
        attachments,
        macHash
    );

    int insertedMessageId = props.DB.insertMessage(message);

    SendMessageResponse response = new SendMessageResponse(nonce, insertedMessageId);

    send(response.json(props.GSON));
  }

  private void receiveMessage(JsonObject requestData, String nonce) throws RequestException, IOException, CriticalDatabaseException, DatabaseException {
    // Get intended message id
    int messageId = GsonUtils.getInt(requestData, "messageId");

    // Get all messages, split between received/sent and create response object
    Message message = props.DB.getMessage(messageId);

    ReceiveMessageResponse response = new ReceiveMessageResponse(nonce, message);

    send(response.json(props.GSON));
  }


  private void sendMessageReceipt(JsonObject requestData) throws RequestException, CriticalDatabaseException, DatabaseException, IOException {
    // Get read message id
    int messageId = GsonUtils.getInt(requestData, "messageId");

    // Get receipt -> message content signature
    String signature = GsonUtils.getString(requestData, "receipt");

    // Get current time
    String date = getDate();

    // Insert message receipt
    props.DB.insertReceipt(new Receipt(messageId, date, signature));

    // No response
  }

  private void getMessageStatus(JsonObject requestData, String nonce) throws RequestException, CriticalDatabaseException, DatabaseException, IOException {
    // Get intended message id
    int messageId = GsonUtils.getInt(requestData, "messageId");

    // TODO Why send the message here? We have a dedicated route....
    // Get the message and its respective receipts
    ArrayList<Receipt> receipts = props.DB.getReceipts(messageId);
    Message message = props.DB.getMessage(messageId);

    // Create response and send
    MessageReceiptsResponse response = new MessageReceiptsResponse(nonce, message, receipts);

    send(response.json(props.GSON));
  }


  // Get all server params
  private synchronized void params(String nonce) throws GeneralSecurityException, CriticalDatabaseException, IOException {
    // Get params and parse to json object
    ServerParameterMap params = props.DB.getAllParameters();
    String paramsJSON = props.GSON.toJson(params);

    // Sign params
    PrivateKey privateKey = props.privateKey();
    byte[] paramsJSONSigBytes = props.AEA.sign(privateKey, paramsJSON.getBytes());
    String paramsJSONSigEncoded = props.B64.encode(paramsJSONSigBytes);

    ParametersResponse response = new ParametersResponse(nonce, paramsJSON, paramsJSONSigEncoded);

    send(response.json(props.GSON));
  }

  /*
    UTILS
  */
  private JsonObject parseRequest(JsonReader reader) throws InvalidFormatException {
    JsonElement data = new JsonParser().parse(reader);

    if (!data.isJsonObject())
      throw new InvalidFormatException();

    return data.getAsJsonObject();
  }

  private void handleException(Exception exception) {
    ErrorResponse response;

    if (exception instanceof IHTTPStatusException) {
      HTTPStatus status = ((IHTTPStatusException) exception).status();
      response = status.buildErrorResponse(exception.getMessage());
    } else {
      System.err.println("Client disconnected due to critical error: " + exception.getMessage());

      if (props.DEBUG_MODE)
        exception.printStackTrace();

      response = HTTPStatus.INTERNAL_SERVER_ERROR.buildErrorResponse();
    }

    String responseJson = response.json(props.GSON);

    try {
      send(responseJson);
    } catch (IOException e) {
      System.err.println("Failed to send error response to client");

      if (props.DEBUG_MODE)
        e.printStackTrace();
    }
  }

  private void send(String message) throws IOException {
    output.write(message.getBytes(StandardCharsets.UTF_8));
  }

  private String getDate() {
    DateFormat df = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");

    return df.format(new Date());
  }
}