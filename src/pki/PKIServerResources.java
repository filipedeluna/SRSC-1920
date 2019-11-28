package pki;

import java.io.IOException;
import java.lang.Thread;
import java.io.OutputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import pki.utils.JsonConverter;
import shared.response.EchoResponse;
import shared.response.ErrorResponse;
import pki.props.PKIProperties;
import shared.errors.request.InvalidFormatException;
import shared.errors.request.InvalidRouteException;
import shared.errors.request.RequestException;
import shared.http.HTTPStatus;

import javax.net.ssl.SSLSocket;

class PKIServerResources implements Runnable {
  private PKIProperties properties;
  private boolean debugMode;

  private SSLSocket client;
  private com.google.gson.stream.JsonReader input;
  private OutputStream output;

  private Gson gson;
  // private PKIServerControl registry;

  PKIServerResources(SSLSocket client, PKIProperties properties, boolean debugMode) {
    this.client = client;
    this.properties = properties;
    this.debugMode = debugMode;
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