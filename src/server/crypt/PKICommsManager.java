package server.crypt;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import server.props.ServerProperty;
import server.request.ValidateCertificateRequest;
import shared.errors.properties.PropertyException;
import shared.errors.request.InvalidFormatException;
import shared.errors.request.RequestException;
import shared.utils.GsonUtils;
import shared.utils.crypto.AEAHelper;
import shared.utils.crypto.B64Helper;
import shared.utils.properties.CustomProperties;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class PKICommsManager {
  private static final int ONE_SECOND = 1000;
  private static final int ONE_MINUTE = 60 * ONE_SECOND;

  private final Logger logger;
  private boolean debug;

  private final Gson gson;
  private final B64Helper b64Helper;
  private AEAHelper aeaHelper;

  private String[] enabledProtocols;
  private String[] enabledCipherSuites;
  private SocketFactory socketFactory;

  private String pkiServerAddress;
  private int pkiServerPort;
  private int pkiTimeout;

  private int pkiCheckValidity;

  private final HashMap<String, Long> checkedClients;

  public PKICommsManager(CustomProperties properties, SSLContext sslContext, Gson gson, AEAHelper aeaHelper, B64Helper b64Helper, Logger logger) throws PropertyException {
    this.logger = logger;
    this.b64Helper = b64Helper;
    this.gson = gson;

    checkedClients = new HashMap<>();
    debug = properties.getBool(ServerProperty.DEBUG);

    // Get socket config
    socketFactory = sslContext.getSocketFactory();
    enabledProtocols = properties.getStringArr(ServerProperty.TLS_PROTOCOLS);
    enabledCipherSuites = properties.getStringArr(ServerProperty.TLS_CIPHERSUITES);

    // Get PKI parameters
    pkiServerAddress = properties.getString(ServerProperty.PKI_SERVER_ADDRESS);
    pkiServerPort = properties.getInt(ServerProperty.PKI_SERVER_PORT);
    pkiCheckValidity = properties.getInt(ServerProperty.PKI_CHECK_VALIDITY) * ONE_MINUTE;
    pkiTimeout = properties.getInt(ServerProperty.PKI_TIMEOUT) * ONE_SECOND;
  }

  public SSLSocket getSocket() throws IOException {
    // Create socket for communication with pki
    SSLSocket sslSocket = (SSLSocket) socketFactory.createSocket(pkiServerAddress, pkiServerPort);

    sslSocket.setEnabledProtocols(enabledProtocols);
    sslSocket.setEnabledCipherSuites(enabledCipherSuites);
    sslSocket.setSoTimeout(pkiTimeout);

    return sslSocket;
  }

  public void checkClientCertificateRevoked(X509Certificate clientCert, SSLSocket socket) throws GeneralSecurityException {
    // No need to check if in cache and valid
    if (certInCache(clientCert))
      return;

    // Get cert encode and send request
    byte[] certBytes = aeaHelper.getCertBytes(clientCert);
    String certEncoded = b64Helper.encode(certBytes);
    String certSN = clientCert.getSerialNumber().toString();

    ValidateCertificateRequest request = new ValidateCertificateRequest(certEncoded);

    try {
      OutputStream output = socket.getOutputStream();
      JsonReader input = new JsonReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));

      String message = request.json(gson);
      output.write(message.getBytes(StandardCharsets.UTF_8));

      // Get response object
      JsonElement data = new JsonParser().parse(input);

      if (!data.isJsonObject())
        throw new InvalidFormatException();

      // Verify validity in response object
      boolean valid = GsonUtils.getBool(data.getAsJsonObject(), "valid");

      if (!valid) {
        logger.log(Level.WARNING, "Refused certificate " + certSN);
        throw new CertificateException("Certificate is not valid - Revoked or never emitted.");
      }

      // Add to cache if valid
      updateCacheEntry(certSN);
    } catch (IOException | RequestException e) {
      if (debug)
        e.printStackTrace();

      logger.log(Level.WARNING, "Failed to verify certificate " + certSN + ": " + e.getMessage());

      throw new CertificateException("Failed to verify Certificate.");
    }
  }

  private synchronized void updateCacheEntry(String certSN) {
    checkedClients.remove(certSN);

    checkedClients.put(certSN, System.currentTimeMillis());
    logger.log(Level.FINE, "Validated certificate: " + certSN);
  }

  private synchronized boolean certInCache(X509Certificate certificate) {
    // Get SN
    String certSN = certificate.getSerialNumber().toString();

    // Check if it is in cache
    if (!checkedClients.containsKey(certSN))
      return false;

    long now = System.currentTimeMillis();

    // Check if still valid
    if (checkedClients.get(certSN) + pkiCheckValidity < now) {
      // Remove old validity first
      checkedClients.remove(certSN);
      return false;
    }

    return true;
  }
}
