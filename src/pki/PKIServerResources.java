package pki;

import java.io.*;
import java.lang.Thread;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;

import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import pki.db.PKIDatabaseDriver;
import pki.props.PKIProperty;
import pki.responses.SignResponse;
import pki.responses.ValidateResponse;
import shared.errors.IHTTPStatusException;
import shared.errors.db.CriticalDatabaseException;
import shared.errors.db.DatabaseException;
import shared.errors.properties.PropertyException;
import shared.errors.request.CustomRequestException;
import shared.response.OKResponse;
import shared.utils.GsonUtils;
import shared.response.EchoResponse;
import shared.response.ErrorResponse;
import shared.errors.request.InvalidRouteException;
import shared.errors.request.RequestException;
import shared.http.HTTPStatus;
import shared.utils.crypto.AEAHelper;
import shared.utils.crypto.Base64Helper;
import shared.utils.crypto.HashHelper;
import shared.utils.properties.CustomProperties;

import javax.net.ssl.SSLSocket;

class PKIServerResources implements Runnable {
  private PKIDatabaseDriver db;
  private boolean debugMode;
  private KeyStore keyStore;

  private SSLSocket client;
  private com.google.gson.stream.JsonReader input;
  private OutputStream output;

  private Gson gson;
  private AEAHelper aeaHelper;
  private HashHelper hashHelper;
  private Base64Helper base64Helper;

  private String keystorePassword;
  private String pkiPubKey;
  private String pkiCert;
  private String token;
  private int certificateValidityDays;

  PKIServerResources(SSLSocket client, CustomProperties properties, KeyStore keyStore, PKIDatabaseDriver db, boolean debugMode) throws GeneralSecurityException, PropertyException {
    this.client = client;
    this.keyStore = keyStore;
    this.db = db;
    this.debugMode = debugMode;

    hashHelper = new HashHelper(properties.getString(PKIProperty.HASH_ALGORITHM));
    gson = GsonUtils.buildGsonInstance();
    base64Helper = new Base64Helper();

    String pubKeyAlg = properties.getString(PKIProperty.PUB_KEY_ALG);
    String certSignAlg = properties.getString(PKIProperty.CERT_SIGN_ALG);
    int pubKeySize = properties.getInt(PKIProperty.PUB_KEY_SIZE);

    aeaHelper = new AEAHelper(pubKeyAlg, certSignAlg, pubKeySize);

    keystorePassword = properties.getString(PKIProperty.KEYSTORE_PASS);
    token = properties.getString(PKIProperty.TOKEN_VALUE);
    pkiPubKey = properties.getString(PKIProperty.PKI_PUB_KEY);
    pkiCert = properties.getString(PKIProperty.PKI_CERT);

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
      JsonObject parsedRequest = GsonUtils.parseRequest(input);

      handleRequest(parsedRequest);

      client.close();
    } catch (Exception e) {
      handleException(e, debugMode);
    }
  }

  private void handleRequest(JsonObject requestData) throws RequestException, IOException, DatabaseException, GeneralSecurityException, CriticalDatabaseException, OperatorException, PKCSException {
    try {
      String requestType = GsonUtils.getString(requestData, "type");

      switch (requestType) {
        case "echo":
          echo(requestData);
          break;
        case "sign":
          sign(requestData);
          break;
        case "validate":
          validate(requestData);
          break;
        case "revoke":
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
  private synchronized void sign(JsonObject requestData) throws RequestException, GeneralSecurityException, DatabaseException, CriticalDatabaseException, IOException, OperatorException, PKCSException {
    // token validity should be verified but is out of work scope.
    // users could purchase a valid token to certify one certificate
    String token = GsonUtils.getString(requestData, "token");

    // We will use a predefined token value for test purposes
    if (!token.equals(this.token))
      throw new CustomRequestException("Invalid token", HTTPStatus.UNAUTHORIZED);

    // Get csr encoded from request and decode it
    String certRequestEncoded = GsonUtils.getString(requestData, "certificationRequest");
    byte[] certRequestBytes = base64Helper.decode(certRequestEncoded);

    PKCS10CertificationRequest certRequest = new PKCS10CertificationRequest(certRequestBytes);

    // Get pki private key and cert and sign csr
    PrivateKey pkiPrivateKey = (PrivateKey) keyStore.getKey(pkiPubKey, keystorePassword.toCharArray());
    X509Certificate pkiCertificate = (X509Certificate) keyStore.getCertificate(pkiCert);

    X509Certificate signedCert =
        aeaHelper.signCSR(certRequest, pkiCertificate, pkiPrivateKey, certificateValidityDays);

    // Get serial number and add to db
    BigInteger serialNumber = signedCert.getSerialNumber();
    String serialNumberString = serialNumber.toString();

    db.register(serialNumberString);

    // encode signed certificate
    byte[] signedCertBytes = aeaHelper.getCertBytes(signedCert);
    String signedCertEncoded = base64Helper.encode(signedCertBytes);

    // Create payload and send response
    SignResponse response = new SignResponse(signedCertEncoded);
    send(response.json(gson));
  }

  // Is Revoked
  private synchronized void validate(JsonObject requestData) throws RequestException, IOException, CriticalDatabaseException, DatabaseException {
    // Get certificate serial number
    String serialNumber = GsonUtils.getString(requestData, "serialNumber");

    // Validate, build and send response
    boolean valid = db.isValid(serialNumber);

    ValidateResponse response = new ValidateResponse(valid);

    send(response.json(gson));
  }

  // Revoke
  private synchronized void revoke(JsonObject requestData) throws RequestException, IOException, DatabaseException, CriticalDatabaseException {
    // token validity should be verified but is out of work scope.
    // this token would be issued to an admin so he could revoke certificates at will
    String token = GsonUtils.getString(requestData, "token");

    // We will use a predefined token value for test purposes
    if (!token.equals(this.token))
      throw new CustomRequestException("Invalid token", HTTPStatus.UNAUTHORIZED);

    // Get certificate and public key
    String serialNumber = GsonUtils.getString(requestData, "serialNumber");

    db.revoke(serialNumber);

    OKResponse response = new OKResponse();

    send(response.json(gson));
  }

  /*
    UTILS
  */


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