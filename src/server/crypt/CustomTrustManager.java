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
import shared.utils.crypto.Base64Helper;
import shared.utils.properties.CustomProperties;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

public class CustomTrustManager implements X509TrustManager {
  private ArrayList<X509Certificate> acceptedIssuers;

  private Base64Helper b64Helper;
  private Gson gson;
  private SSLSocket socket;
  private boolean debug;

  public CustomTrustManager(CustomProperties properties, SSLSocketFactory socketFactory, Base64Helper b64Helper, Gson gson) throws PropertyException, IOException {
    // Create socket
    String pkiServerAddress = properties.getString(ServerProperty.PKI_SERVER_ADDRESS);
    int pkiServerPort = properties.getInt(ServerProperty.PKI_SERVER_PORT);

    socket = (SSLSocket) socketFactory.createSocket(pkiServerAddress, pkiServerPort);
    debug = properties.getBool(ServerProperty.DEBUG);
    this.b64Helper = b64Helper;
    this.gson = gson;
  }

  @Override
  public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
    X509Certificate clientCert = x509Certificates[0];

    try {
      socket.startHandshake();
      OutputStream output = socket.getOutputStream();
      JsonReader input = new JsonReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));

      // Get cert sn, build and send request
      String certSN = clientCert.getSerialNumber().toString();
      ValidateCertificateRequest request = new ValidateCertificateRequest(certSN);

      String message = request.json(gson);
      output.write(message.getBytes(StandardCharsets.UTF_8));

      // Get response object
      JsonElement data = new JsonParser().parse(input);

      if (!data.isJsonObject())
        throw new InvalidFormatException();

      boolean valid = GsonUtils.getBool(data.getAsJsonObject(), "valid");

      if (!valid)
        throw new CertificateException("Not valid.");

    } catch (IOException | RequestException e) {
      if (debug)
        e.printStackTrace();

      throw new CertificateException("Failed to verify.");
    }
  }

  @Override
  public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

  }

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    return (X509Certificate[]) acceptedIssuers.toArray();
  }
}
