package server;

import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import server.db.ServerDatabaseDriver;
import server.props.ServerProperty;
import shared.errors.IHTTPStatusException;
import shared.errors.db.CriticalDatabaseException;
import shared.errors.db.DatabaseException;
import shared.errors.properties.PropertyException;
import shared.errors.request.InvalidFormatException;
import shared.errors.request.InvalidRouteException;
import shared.errors.request.RequestException;
import shared.http.HTTPStatus;
import shared.response.EchoResponse;
import shared.response.ErrorResponse;
import shared.utils.GsonUtils;
import shared.utils.crypto.AEAHelper;
import shared.utils.crypto.Base64Helper;
import shared.utils.crypto.HashHelper;
import shared.utils.properties.CustomProperties;

import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

class ServerResources implements Runnable {
  private ServerDatabaseDriver db;
  private boolean debugMode;
  private KeyStore keyStore;

  private SSLSocket client;
  private JsonReader input;
  private OutputStream output;

  private Gson gson;
  private AEAHelper aeaHelper;
  private HashHelper hashHelper;
  private Base64Helper base64Helper;

  private String keystorePassword;
  private String token;

  ServerResources(SSLSocket client, CustomProperties properties, KeyStore keyStore, ServerDatabaseDriver db, boolean debugMode) throws GeneralSecurityException, PropertyException {
    this.client = client;
    this.keyStore = keyStore;
    this.db = db;
    this.debugMode = debugMode;

    hashHelper = new HashHelper(properties.getString(ServerProperty.HASH_ALG));

    String pubKeyAlg = properties.getString(ServerProperty.PUB_KEY_ALG);
    String certSignAlg = properties.getString(ServerProperty.CERT_SIGN_ALG);
    int pubKeySize = properties.getInt(ServerProperty.PUB_KEY_SIZE);

    aeaHelper = new AEAHelper(pubKeyAlg, certSignAlg, pubKeySize);

    gson = GsonUtils.buildGsonInstance();
    base64Helper = new Base64Helper();
    try {
      input = new JsonReader(new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));
      output = client.getOutputStream();
    } catch (Exception e) {
      handleException(e, debugMode);
      Thread.currentThread().interrupt();
    }
  }

  public void run() {
    try {
      JsonObject parsedRequest = parseRequest(input);

      handleRequest(parsedRequest);

      client.close();
    } catch (Exception e) {
      handleException(e, debugMode);
    }
  }

  private void handleRequest(JsonObject requestData) throws RequestException, IOException, DatabaseException, GeneralSecurityException, CriticalDatabaseException {
    try {
      String requestType = GsonUtils.getString(requestData, "type");

      switch (requestType) {
        case "echo":
          echo(requestData);
          break;
        case "create":
          sign(requestData);
          break;
        case "list":
          validate(requestData);
          break;
        case "new":
          revoke(requestData);
          break;
        case "all":
          revoke(requestData);
          break;
        case "send":
          revoke(requestData);
          break;
        case "recv":
          revoke(requestData);
          break;
        case "receipt":
          revoke(requestData);
          break;
        case "status":
          revoke(requestData);
          break;

        default:
          throw new InvalidRouteException();
      }
    } catch (ClassCastException | IllegalStateException e) {
      throw new InvalidRouteException();
    }
  }

  // Echo
  private void echo(JsonObject requestData) throws RequestException, IOException {
    String message = GsonUtils.getString(requestData, "message");

    EchoResponse response = new EchoResponse(message);

    send(response.json(gson));
  }

  // Register
  private synchronized void sign(JsonObject requestData) throws RequestException, GeneralSecurityException, DatabaseException, CriticalDatabaseException, IOException {

  }

  // Is Revoked
  private synchronized void validate(JsonObject requestData) throws RequestException, IOException, CriticalDatabaseException {

  }

  // Revoke
  private synchronized void revoke(JsonObject requestData) throws RequestException, IOException, DatabaseException, CriticalDatabaseException {

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

  private void handleException(Exception exception, boolean debugMode) {
    ErrorResponse response;

    if (exception instanceof IHTTPStatusException) {
      HTTPStatus status = ((IHTTPStatusException) exception).status();
      response = status.buildErrorResponse(exception.getMessage());
    } else {
      System.err.println("Client disconnected due to critical error: " + exception.getMessage());

      if (debugMode)
        exception.printStackTrace();

      response = HTTPStatus.INTERNAL_SERVER_ERROR.buildErrorResponse();
    }

    String responseJson = response.json(gson);

    try {
      send(responseJson);
    } catch (IOException e) {
      System.err.println("Failed to send error response to client");

      if (debugMode)
        e.printStackTrace();
    }
  }

  private void send(String message) throws IOException {
    output.write(message.getBytes(StandardCharsets.UTF_8));
  }
}