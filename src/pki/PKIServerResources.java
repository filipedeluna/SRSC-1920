package pki;

import java.io.IOException;
import java.lang.Thread;
import java.io.OutputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import pki.db.PKIDatabaseDriver;
import shared.utils.JsonConverter;
import shared.response.EchoResponse;
import shared.response.ErrorResponse;
import pki.props.PKIProperties;
import shared.errors.request.InvalidFormatException;
import shared.errors.request.InvalidRouteException;
import shared.errors.request.RequestException;
import shared.http.HTTPStatus;
import sun.security.provider.X509Factory;

import javax.net.ssl.SSLSocket;

class PKIServerResources implements Runnable {
  private static final char[] GLOBAL_PASSWORD = "123asd".toCharArray();
  private static final String PUB_KEY = "pkipub";

  private PKIProperties properties;
  private PKIDatabaseDriver db;
  private boolean debugMode;
  private KeyStore keyStore;

  private SSLSocket client;
  private com.google.gson.stream.JsonReader input;
  private OutputStream output;

  private Gson gson;

  PKIServerResources(SSLSocket client, PKIProperties properties, KeyStore keyStore, PKIDatabaseDriver db, boolean debugMode) {
    this.client = client;
    this.properties = properties;
    this.db = db;
    this.debugMode = debugMode;
    this.keyStore = keyStore;

    this.gson = buildGsonInstance();

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

  private void handleRequest(JsonObject requestData) throws RequestException, IOException {
    try {
      String requestType = JsonConverter.getString(requestData, "type");

      switch (requestType) {
        case "echo":
          echo(requestData);
          break;
        case "register":
          break;
        case "revoked":
          break;
        case "revoke":
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
    String message = JsonConverter.getString(requestData, "message");

    EchoResponse response = new EchoResponse(message);

    send(response.json(gson));
  }

  // Register
  private synchronized void register(JsonObject requestData) throws RequestException, IOException, GeneralSecurityException {
    String username = JsonConverter.getString(requestData, "username");
    String cert = JsonConverter.getString(requestData, "cert");
    String token = JsonConverter.getString(requestData, "token");

    // token validity should be verified but is out of work scope.
    // users could purchase a valid token to certify one certificate


    Certificate x509Cert = keyStore.
    //
    PrivateKey key = (PrivateKey) keyStore.getKey(PUB_KEY, GLOBAL_PASSWORD);


    send(response.json(gson));
  }

  // Is Revoked
  private void isRevoked(JsonObject requestData) throws RequestException, IOException {
    String message = JsonConverter.getString(requestData, "message");

    EchoResponse response = new EchoResponse(message);

    send(response.json(gson));
  }

  // Revoke
  private void revoke(JsonObject requestData) throws RequestException, IOException {
    String message = JsonConverter.getString(requestData, "message");

    EchoResponse response = new EchoResponse(message);

    send(response.json(gson));
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

    if (exception instanceof RequestException) {
      HTTPStatus status = ((RequestException) exception).status();
      response = new ErrorResponse(status, exception.getMessage());
    } else {
      System.err.println("Client disconnected due to critical error: " + exception.getMessage());

      if (debugMode)
        exception.printStackTrace();

      HTTPStatus status = HTTPStatus.INTERNAL_SERVER_ERROR;
      response = new ErrorResponse(status, status.message());
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

  private Gson buildGsonInstance() {
    return new GsonBuilder()
        .serializeNulls()
        .setFieldNamingPolicy(FieldNamingPolicy.IDENTITY)
        .setPrettyPrinting()
        .create();
  }
}