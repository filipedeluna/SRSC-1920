package server.crypt;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import server.props.ServerProperty;
import server.request.ValidateCertificateRequest;
import shared.errors.properties.PropertyException;
import shared.errors.request.CustomRequestException;
import shared.errors.request.InvalidFormatException;
import shared.errors.request.RequestException;
import shared.http.HTTPStatus;
import shared.utils.GsonUtils;
import shared.utils.crypto.B64Helper;
import shared.utils.crypto.util.CertificateEntry;
import shared.utils.properties.CustomProperties;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class PKICommsManager {
  private static final int ONE_SECOND = 1000;
  private static final int ONE_HOUR = 60 * 60 * ONE_SECOND;

  private final Logger logger;
  private boolean debug;

  private final Gson gson;
  private final B64Helper b64Helper;

  private String[] enabledProtocols;
  private String[] enabledCipherSuites;
  private SocketFactory socketFactory;

  private String pkiServerAddress;
  private int pkiServerPort;
  private int pkiTimeout;
  private int pkiCheckValidity;

  private HashMap<String, CertificateEntry> certCache;

  public PKICommsManager(CustomProperties properties, SSLContext sslContext, Logger logger) throws PropertyException {
    this.logger = logger;
    this.b64Helper = new B64Helper();
    this.gson = GsonUtils.buildGsonInstance();

    certCache = new HashMap<>();
    debug = properties.getBool(ServerProperty.DEBUG);

    // Get socket config
    socketFactory = sslContext.getSocketFactory();
    enabledProtocols = properties.getStringArr(ServerProperty.TLS_PROTOCOLS);
    enabledCipherSuites = properties.getStringArr(ServerProperty.TLS_CIPHERSUITES);

    // Get PKI parameters
    pkiServerAddress = properties.getString(ServerProperty.PKI_SERVER_ADDRESS);
    pkiServerPort = properties.getInt(ServerProperty.PKI_SERVER_PORT);
    pkiTimeout = properties.getInt(ServerProperty.PKI_TIMEOUT) * ONE_SECOND;
    pkiCheckValidity = properties.getInt(ServerProperty.PKI_CHECK_VALIDITY) * ONE_HOUR;
  }

  public SSLSocket getSocket() throws IOException {
    // Create socket for communication with pki
    SSLSocket sslSocket = (SSLSocket) socketFactory.createSocket(pkiServerAddress, pkiServerPort);

    sslSocket.setEnabledProtocols(enabledProtocols);
    sslSocket.setEnabledCipherSuites(enabledCipherSuites);
    sslSocket.setSoTimeout(pkiTimeout);

    return sslSocket;
  }

  public void checkClientCertificateRevoked(X509Certificate clientCert, SSLSocket socket) throws CustomRequestException, IOException {
    // Get cert sn to verify if it is in cache
    String certSN = clientCert.getSerialNumber().toString();

    try {
      // Certificate found in cache
      if (certCache.containsKey(certSN)) {
        CertificateEntry certificate = certCache.get(certSN);

        // Check if certificate validity is over
        try {
          certificate.getCertificate().checkValidity();
        } catch (CertificateNotYetValidException | CertificateExpiredException e) {
          throw new CustomRequestException("Certificate has expired.", HTTPStatus.UNAUTHORIZED);
        }

        // Check if certificate cache validity expired
        if (certificate.stillValid(pkiCheckValidity)) {
          // Certificate is valid
          logger.log(Level.WARNING, "Certificate successfully validated - " + certSN);
          return;
        }

        // Certificate is not valid, remove from cache and got ot PKI to get it
        logger.log(Level.WARNING, "Certificate cache validity expired - " + certSN);
        certCache.remove(certSN);
      }

      // Certificate not in cache, get it from the PKI
      byte[] certBytes;
      try {
        certBytes = clientCert.getEncoded();
      } catch (CertificateEncodingException e) {
        throw new CustomRequestException("Certificate is not valid due to corrupted encoding.", HTTPStatus.UNAUTHORIZED);
      }

      String certEncoded = b64Helper.encode(certBytes);

      // Build request to validate certificate and send it
      ValidateCertificateRequest request = new ValidateCertificateRequest(certEncoded);

      OutputStream output = socket.getOutputStream();
      JsonReader input = new JsonReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));

      String message = request.json(gson);
      output.write(message.getBytes(StandardCharsets.UTF_8));

      // Get response object
      JsonElement data = new JsonParser().parse(input);

      if (!data.isJsonObject())
        throw new CustomRequestException("Failed to verify Certificate due to PKI response corruption.", HTTPStatus.UNAUTHORIZED);

      // Verify validity in response object
      boolean valid = GsonUtils.getBool(data.getAsJsonObject(), "valid");

      if (!valid)
        throw new CustomRequestException("Certificate revoked or never emitted.", HTTPStatus.UNAUTHORIZED);

      // Certificate is valid, insert in cache
      certCache.put(certSN, new CertificateEntry(clientCert));
      logger.log(Level.WARNING, "Certificate successfully validated - " + certSN);

    } catch (RequestException e) {
      logger.log(Level.WARNING, "Failed to validate certificate " + certSN + ": " + e.getMessage());

      if (debug)
        e.printStackTrace();

      if (e instanceof CustomRequestException)
        throw (CustomRequestException) e;
    }
  }
}
