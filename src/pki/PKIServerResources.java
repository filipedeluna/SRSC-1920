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
import pki.responses.SignResponse;
import pki.responses.ValidateResponse;
import shared.errors.IHTTPStatusException;
import shared.errors.db.CriticalDatabaseException;
import shared.errors.db.DatabaseException;
import shared.errors.request.CustomRequestException;
import shared.response.OKResponse;
import shared.utils.GsonUtils;
import shared.response.ErrorResponse;
import shared.errors.request.InvalidRouteException;
import shared.errors.request.RequestException;
import shared.http.HTTPStatus;
import shared.utils.SafeInputStreamReader;

import javax.net.ssl.SSLSocket;

final class PKIServerResources implements Runnable {
  private SSLSocket client;
  private com.google.gson.stream.JsonReader input;
  private OutputStream output;

  private PKIServerProperties props;

  PKIServerResources(SSLSocket client, PKIServerProperties props) {
    this.client = client;
    this.props = props;

    try {
      // We should not allow large transfers in order to avoid DoS
      int maxBufferSizeInMB = 1;

      input = new JsonReader(new SafeInputStreamReader(client.getInputStream(), maxBufferSizeInMB));
      output = client.getOutputStream();
    } catch (Exception e) {
      handleException(e, props.DEBUG_MODE);
      Thread.currentThread().interrupt();
    }
  }

  public void run() {
    try {
      JsonObject parsedRequest = GsonUtils.parseRequest(input);

      handleRequest(parsedRequest);

      client.close();
    } catch (Exception e) {
      handleException(e, props.DEBUG_MODE);
    }
  }

  private void handleRequest(JsonObject requestData) throws RequestException, IOException, DatabaseException, GeneralSecurityException, CriticalDatabaseException, OperatorException, PKCSException {
    try {
      String requestType = GsonUtils.getString(requestData, "type");

      switch (requestType) {
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

  // Register
  private synchronized void sign(JsonObject requestData) throws RequestException, GeneralSecurityException, DatabaseException, CriticalDatabaseException, IOException, OperatorException, PKCSException {
    // token validity should be verified but is out of work scope.
    // users could purchase a valid token to certify one certificate
    String token = GsonUtils.getString(requestData, "token");

    // We will use a predefined token value for test purposes
    if (!props.validToken(token))
      throw new CustomRequestException("Invalid token", HTTPStatus.UNAUTHORIZED);

    // Get csr encoded from request and decode it
    String certRequestEncoded = GsonUtils.getString(requestData, "certificationRequest");
    byte[] certRequestBytes = props.B64.decode(certRequestEncoded);

    PKCS10CertificationRequest certRequest = new PKCS10CertificationRequest(certRequestBytes);

    // Sign csr
    X509Certificate signedCert =
        props.AEA.signCSR(certRequest, props.CERT, props.privateKey(), props.CERT_VALIDATY);

    // Get serial number and add to db
    BigInteger serialNumber = signedCert.getSerialNumber();
    String serialNumberString = serialNumber.toString();

    props.DB.register(serialNumberString);

    // encode signed certificate
    byte[] signedCertBytes = props.AEA.getCertBytes(signedCert);
    String signedCertEncoded = props.B64.encode(signedCertBytes);

    // Create payload and send response
    SignResponse response = new SignResponse(signedCertEncoded);
    send(response.json(props.GSON));
  }

  // Is Revoked
  private void validate(JsonObject requestData) throws RequestException, IOException, CriticalDatabaseException, DatabaseException {
    // Get certificate serial number
    String serialNumber = GsonUtils.getString(requestData, "serialNumber");

    // Validate, build and send response
    boolean valid = props.DB.isValid(serialNumber);

    ValidateResponse response = new ValidateResponse(valid);

    send(response.json(props.GSON));
  }

  // Revoke
  private synchronized void revoke(JsonObject requestData) throws RequestException, IOException, DatabaseException, CriticalDatabaseException {
    // token validity should be verified but is out of work scope.
    // this token would be issued to an admin so he could revoke certificates at will
    String token = GsonUtils.getString(requestData, "token");

    // We will use a predefined token value for test purposes
    if (!props.validToken(token))
      throw new CustomRequestException("Invalid token", HTTPStatus.UNAUTHORIZED);

    // Get certificate and public key
    String serialNumber = GsonUtils.getString(requestData, "serialNumber");

    props.DB.revoke(serialNumber);

    OKResponse response = new OKResponse();

    send(response.json(props.GSON));
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

    String responseJson = response.json(props.GSON);

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