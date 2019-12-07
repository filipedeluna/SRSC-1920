package pki;

import java.io.*;
import java.lang.Thread;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;

import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import pki.responses.SignResponse;
import pki.responses.ValidateResponse;
import shared.errors.IHTTPStatusException;
import shared.errors.db.CriticalDatabaseException;
import shared.errors.db.DatabaseException;
import shared.errors.request.CustomRequestException;
import shared.response.GsonResponse;
import shared.response.OKResponse;
import shared.utils.GsonUtils;
import shared.response.ErrorResponse;
import shared.errors.request.InvalidRouteException;
import shared.errors.request.RequestException;
import shared.http.HTTPStatus;
import shared.utils.SafeInputStreamReader;

import javax.net.ssl.SSLSocket;

import static org.bouncycastle.asn1.x500.style.RFC4519Style.serialNumber;

final class PKIServerResources implements Runnable {
  private final SSLSocket client;
  private com.google.gson.stream.JsonReader input;
  private OutputStream output;

  private final PKIServerProperties props;

  PKIServerResources(SSLSocket client, PKIServerProperties props) {
    this.client = client;
    this.props = props;

    try {
      // We should not allow large transfers in order to avoid DoS
      int maxBufferSizeInMB = 1;

      input = new JsonReader(new SafeInputStreamReader(client.getInputStream(), maxBufferSizeInMB));
      output = client.getOutputStream();
    } catch (Exception e) {
      handleException(e);
    }
  }

  public void run() {
    try {
      JsonObject parsedRequest = GsonUtils.parseRequest(input);

      handleRequest(parsedRequest);

      client.close();
    } catch (Exception e) {
      handleException(e);
      Thread.currentThread().interrupt();
    }
  }

  private void handleRequest(JsonObject requestData) throws RequestException, IOException, GeneralSecurityException, CriticalDatabaseException, OperatorException {
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
  private synchronized void sign(JsonObject requestData) throws RequestException, GeneralSecurityException, IOException, OperatorCreationException, CriticalDatabaseException {
    // token validity should be verified but is out of work scope.
    // users could purchase a valid token to certify one certificate
    String token = GsonUtils.getString(requestData, "token");

    // We will use a predefined token value for test purposes
    if (!props.isTokenValid(token))
      throw new CustomRequestException("Invalid token", HTTPStatus.UNAUTHORIZED);

    // Get csr encoded from request and decode it
    String certRequestEncoded = GsonUtils.getString(requestData, "certificationRequest");
    byte[] certRequestBytes = props.b64Helper.decode(certRequestEncoded);

    // Get CSR from bytes
    PKCS10CertificationRequest certRequest;
    try {
      certRequest = props.aeaHelper.csrFromBytes(certRequestBytes);
    } catch (IOException e) {
      throw new CustomRequestException("CSR is corrupted", HTTPStatus.BAD_REQUEST);
    }

    // Attempt to create signed CSR
    X509Certificate signedCert;
    try {
      signedCert = props.aeaHelper.signCSR(certRequest, props.CERT, props.privateKey(), props.CERT_VALIDITY);
    } catch (PKCSException e) {
      throw new CustomRequestException("CSR signature is invalid", HTTPStatus.BAD_REQUEST);
    }

    // Get cert SN and hash
    byte[] certBytes = props.aeaHelper.getCertBytes(signedCert);
    String certHashEncoded = props.hashHelper.hashAndEncode(certBytes);
    String certSN = props.aeaHelper.getCertSN(signedCert);

    // Attempt to register CSR
    try {
      props.DB.register(certSN, certHashEncoded);
    } catch (DatabaseException e) {
      throw new CustomRequestException("Duplicate certificate serial number", HTTPStatus.BAD_REQUEST);
    }

    // encode signed certificate
    byte[] signedCertBytes = props.aeaHelper.getCertBytes(signedCert);
    String signedCertEncoded = props.b64Helper.encode(signedCertBytes);

    // Create payload and send response
    send(new SignResponse(signedCertEncoded));

    props.logger.log(Level.FINE, "Certificate emitted with SN " + serialNumber);
  }

  // Is Revoked
  private void validate(JsonObject requestData) throws RequestException, IOException, CriticalDatabaseException, InvalidKeyException, NoSuchProviderException, NoSuchAlgorithmException {
    // Get certificate and decode it
    String certEncoded = GsonUtils.getString(requestData, "certificate");
    byte[] certDecoded = props.b64Helper.decode(certEncoded);

    // Build certificate and get serial number and build hash
    X509Certificate certificate;
    try {
      certificate = props.aeaHelper.getCertFromBytes(certDecoded);
    } catch (CertificateException e) {
      throw new CustomRequestException("Certificate is corrupted.", HTTPStatus.BAD_REQUEST);
    }

    String certSN = props.aeaHelper.getCertSN(certificate);
    String certHash = props.hashHelper.hashAndEncode(certDecoded);

    // Check cert belongs to public key
    try {
      certificate.verify(props.PUB_KEY);

      // Look for certificate in Revocation DB
      boolean valid = props.DB.isValid(certSN, certHash);

      send(new ValidateResponse(valid));

      props.logger.log(Level.FINE, "Certificate " + certSN + " validated");
    } catch (CertificateException | SignatureException e) {
      // Cert does not belong to CA
      send(new ValidateResponse(false));
      props.logger.log(Level.FINE, "Certificate " + certSN + " not validated");
    }
  }

  // Revoke
  private synchronized void revoke(JsonObject requestData) throws RequestException, IOException, CriticalDatabaseException {
    // token validity should be verified but is out of work scope.
    // this token would be issued to an admin so he could revoke certificates at will
    String token = GsonUtils.getString(requestData, "token");

    // We will use a predefined token value for test purposes
    if (!props.isTokenValid(token))
      throw new CustomRequestException("Invalid token", HTTPStatus.UNAUTHORIZED);

    // Get certificate and public key
    String serialNumber = GsonUtils.getString(requestData, "serialNumber");

    try {
      props.DB.revoke(serialNumber);
    } catch (DatabaseException e) {
      throw new CustomRequestException("Certificate not found.", HTTPStatus.NOT_FOUND);
    }

    send(new OKResponse());

    props.logger.log(Level.FINE, "Certificate revoked with SN " + serialNumber);
  }

  /*
    UTILS
  */
  private void handleException(Exception exception) {
    ErrorResponse response;

    if (exception instanceof IHTTPStatusException) {
      HTTPStatus status = ((IHTTPStatusException) exception).status();
      response = status.buildErrorResponse(exception.getMessage());

      props.logger.log(Level.WARNING, exception.getMessage());
    } else {
      System.err.println("Client disconnected due to critical error: " + exception.getMessage());

      if (props.DEBUG_MODE)
        exception.printStackTrace();

      response = HTTPStatus.INTERNAL_SERVER_ERROR.buildErrorResponse();
      props.logger.log(Level.SEVERE, exception.getMessage());
    }

    try {
      send(response);
    } catch (IOException e) {
      System.err.println("Failed to send error response to client");
      props.logger.log(Level.SEVERE, exception.getMessage());

      if (props.DEBUG_MODE)
        e.printStackTrace();
    }
  }

  private void send(GsonResponse response) throws IOException {
    output.write(response.json(props.GSON).getBytes(StandardCharsets.UTF_8));
  }
}