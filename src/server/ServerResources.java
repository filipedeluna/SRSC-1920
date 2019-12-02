package server;

import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import server.response.ParametersResponse;
import shared.errors.IHTTPStatusException;
import shared.errors.db.CriticalDatabaseException;
import shared.errors.db.DatabaseException;
import shared.errors.properties.PropertyException;
import shared.errors.request.CustomRequestException;
import shared.errors.request.InvalidFormatException;
import shared.errors.request.InvalidRouteException;
import shared.errors.request.RequestException;
import shared.http.HTTPStatus;
import shared.response.EchoResponse;
import shared.response.ErrorResponse;
import shared.utils.CryptUtil;
import shared.utils.GsonUtils;

import javax.net.ssl.SSLSocket;
import java.security.*;
import java.security.cert.X509Certificate;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;

class ServerResources implements Runnable {
  private SSLSocket client;
  private JsonReader input;
  private OutputStream output;

  private ServerProperties props;

  ServerResources(SSLSocket client, ServerProperties props) {
    this.client = client;
    this.props = props;

    try {
      input = new JsonReader(new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));
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
      String requestType = GsonUtils.getString(requestData, "type");

      switch (requestType) {
        case "echo":
          echo(requestData);
          break;
        case "create":
          create(requestData);
          break;
        case "list":
          validate(requestData);
          break;
        case "new":
          validate(requestData);
          break;
        case "all":
          validate(requestData);
          break;
        case "send":
          validate(requestData);
          break;
        case "recv":
          validate(requestData);
          break;
        case "receipt":
          validate(requestData);
          break;
        case "status":
          validate(requestData);
          break;
        case "params":
          params(requestData);
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

    send(response.json(props.GSON));
  }

  // Create user message box
  private synchronized void create(JsonObject requestData) throws RequestException, GeneralSecurityException, DatabaseException, CriticalDatabaseException, IOException {
    // Get public key and certificate from user
    X509Certificate certificate = (X509Certificate) client.getSession().getPeerCertificates()[0];
    PublicKey publicKey = certificate.getPublicKey();

    // Get user intended uuid and message verification nonce
    String uuid = GsonUtils.getString(requestData, "uuid");
    String nonce = GsonUtils.getString(requestData, "nonce");

    // Get extra fields
    String dhValue = GsonUtils.getString(requestData, "dhValue");

    // Get extra fields signature
    String signature = GsonUtils.getString(requestData, "signature");
    byte[] signatureBytes = props.B64.decode(signature);

    // Join extra fields bytes and verify signature
    byte[] extraFieldsBytes = CryptUtil.joinByteArrays(
        dhValue.getBytes()
    );

    if (!props.AEA.verifySignature(publicKey, extraFieldsBytes, signatureBytes))
      throw new CustomRequestException("Data signature is not valid.", HTTPStatus.UNAUTHORIZED);

    // TODO insert user

  }

  // Is Revoked
  private synchronized void validate(JsonObject requestData) throws RequestException, IOException, CriticalDatabaseException {

  }

  // Revoke
  private synchronized void params(JsonObject requestData) throws GeneralSecurityException, CriticalDatabaseException, RequestException, IOException {
    String nonce = GsonUtils.getString(requestData, "nonce");

    // Get params and parse to json object
    HashMap<String, String> params = props.DB.getAllParameters();
    String paramsJSON = props.GSON.toJson(params);

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
}