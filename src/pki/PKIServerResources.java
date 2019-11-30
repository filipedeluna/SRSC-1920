package pki;

import java.io.*;
import java.lang.Thread;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;

import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import pki.db.PKIDatabaseDriver;
import pki.props.PKIProperty;
import pki.responses.SignResponse;
import pki.responses.ValidateResponse;
import shared.errors.IHTTPStatusException;
import shared.errors.db.CriticalDatabaseException;
import shared.errors.db.DatabaseException;
import shared.errors.properties.PropertyException;
import shared.errors.request.CustomRequestException;
import shared.utils.JsonConverter;
import shared.response.EchoResponse;
import shared.response.ErrorResponse;
import pki.props.PKIProperties;
import shared.errors.request.InvalidFormatException;
import shared.errors.request.InvalidRouteException;
import shared.errors.request.RequestException;
import shared.http.HTTPStatus;
import shared.utils.crypto.Base64Helper;
import shared.utils.crypto.CertificateHelper;
import shared.utils.crypto.HashHelper;

import javax.net.ssl.SSLSocket;

class PKIServerResources implements Runnable {
  private static final String GLOBAL_PASSWORD_STRING = "123asd";
  private static final char[] GLOBAL_PASSWORD = GLOBAL_PASSWORD_STRING.toCharArray();

  private static final String PKI_PUB_KEY = "pkipub";
  private static final String PKI_CERT = "pkicert";

  private PKIProperties properties;
  private PKIDatabaseDriver db;
  private boolean debugMode;
  private KeyStore keyStore;

  private SSLSocket client;
  private com.google.gson.stream.JsonReader input;
  private OutputStream output;

  private Gson gson;
  private CertificateHelper certificateHelper;
  private HashHelper hashHelper;
  private Base64Helper base64Helper;

  PKIServerResources(SSLSocket client, PKIProperties properties, KeyStore keyStore, PKIDatabaseDriver db, boolean debugMode) throws GeneralSecurityException, PropertyException {
    this.client = client;
    this.properties = properties;
    this.keyStore = keyStore;
    this.db = db;
    this.debugMode = debugMode;

    hashHelper = new HashHelper(properties.getString(PKIProperty.HASH_ALGORITHM));
    certificateHelper = new CertificateHelper();
    gson = buildGsonInstance();

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
      String requestType = JsonConverter.getString(requestData, "type");

      switch (requestType) {
        case "echo":
          echo(requestData);
          break;
        case "sign":
          sign(requestData);
          break;
        case "validate":
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
  private synchronized void sign(JsonObject requestData) throws RequestException, GeneralSecurityException, DatabaseException, CriticalDatabaseException, IOException {
    // token validity should be verified but is out of work scope.
    // users could purchase a valid token to certify one certificate
    String token = JsonConverter.getString(requestData, "token");

    // We will use a predefined token value for test purposes
    if (!token.equals(GLOBAL_PASSWORD_STRING))
      throw new CustomRequestException("Invalid token", HTTPStatus.UNAUTHORIZED);

    // Get public key and certificate and decode them
    String publicKeyEncoded = JsonConverter.getString(requestData, "publicKey");
    String certificateEncoded = JsonConverter.getString(requestData, "certificate");
    byte[] publicKeyBytes = base64Helper.decode(publicKeyEncoded);
    byte[] certificateBytes = base64Helper.decode(certificateEncoded);

    // Generate cert and public key and verify if public key and cert match
    PublicKey certPublicKey = certificateHelper.RSAKeyFromBytes(publicKeyBytes);
    X509Certificate certificate = certificateHelper.fromBytes(certificateBytes);

    if (!certificateHelper.validate(certPublicKey, certificate))
      throw new CustomRequestException("Public key does not match certificate", HTTPStatus.BAD_REQUEST);

    // Sign certificate
    PrivateKey pkiPrivateKey = (PrivateKey) keyStore.getKey(PKI_PUB_KEY, GLOBAL_PASSWORD);
    X509Certificate pkiCertificate = (X509Certificate) keyStore.getCertificate(PKI_CERT);

    X509Certificate signedCertificate = certificateHelper.signCertificate(certificate, pkiCertificate, pkiPrivateKey);

    // Hash and encode certificate and public key to register entry in db
    byte[] signedCertBytes = signedCertificate.getTBSCertificate();
    byte[] signedCertHashBytes = hashHelper.hash(signedCertBytes);
    byte[] publicKeyHashBytes = hashHelper.hash(publicKeyBytes);

    String signedCertHashEncoded = base64Helper.encode(signedCertHashBytes);
    String publicKeyHashEncoded = base64Helper.encode(publicKeyHashBytes);

    db.register(publicKeyHashEncoded, signedCertHashEncoded);

    // Create payload and send response
    SignResponse response = new SignResponse(signedCertHashEncoded);
    send(response.json(gson));
  }

  // Is Revoked
  private void validate(JsonObject requestData) throws RequestException, IOException, CriticalDatabaseException {
    // Get certificate and decode to bytes
    String certificateEncoded = JsonConverter.getString(requestData, "certificate");
    byte[] certificateBytes = base64Helper.decode(certificateEncoded);

    // Hash certificate and check if valid
    byte[] certificateHash = hashHelper.hash(certificateBytes);
    String certificateHashEncoded = base64Helper.encode(certificateHash);

    // Validate, build and send response
    boolean valid = db.isValid(certificateHashEncoded);

    ValidateResponse response = new ValidateResponse(valid);

    send(response.json(gson));
  }

  // Revoke
  private void revoke(JsonObject requestData) throws RequestException, IOException {
    // token validity should be verified but is out of work scope.
    // users could purchase a valid token to certify one certificate
    String token = JsonConverter.getString(requestData, "token");

    // We will use a predefined token value for test purposes
    if (!token.equals(GLOBAL_PASSWORD_STRING))
      throw new CustomRequestException("Invalid token", HTTPStatus.UNAUTHORIZED);

    String certificateEncoded = JsonConverter.getString(requestData, "certificate");

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

  private Gson buildGsonInstance() {
    return new GsonBuilder()
        .serializeNulls()
        .setFieldNamingPolicy(FieldNamingPolicy.IDENTITY)
        .setPrettyPrinting()
        .create();
  }
}