package client;

import client.props.ClientProperty;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.stream.JsonReader;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import server.crypt.CustomTrustManager;
import server.db.ServerDatabaseDriver;
import server.response.ParametersResponse;
import shared.errors.properties.InvalidValueException;
import shared.errors.properties.PropertyException;
import shared.errors.request.InvalidFormatException;
import shared.utils.CryptUtil;
import shared.utils.GsonUtils;
import shared.utils.SafeInputStreamReader;
import shared.utils.crypto.AEAHelper;
import shared.utils.crypto.B4Helper;
import shared.utils.properties.CustomProperties;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public class Client {
  private static final String PROPS_PATH = "src/client/props/client.properties";

  public static void main(String[] args) {

    System.setProperty("java.net.preferIPv4Stack", "true");
    Security.addProvider(new BouncyCastleJsseProvider());

    // Get properties from file
    CustomProperties properties = null;
    boolean debugMode = false;

    try {
      properties = new CustomProperties(PROPS_PATH);
      debugMode = properties.getBool(ClientProperty.DEBUG);
    } catch (PropertyException e) {
      System.err.println(e.getMessage());
      System.exit(-1);
    }
    try {
      // Gets the client keystore
      KeyStore keyStore = getKeyStore(properties);

      // Create SSL Socket
      int serverport = properties.getInt(ClientProperty.PORT);
      SSLContext sslContext = buildSSLContext(properties, keyStore);
      SSLSocketFactory factory = sslContext.getSocketFactory();
      SSLSocket socket = (SSLSocket) factory.createSocket("localhost", serverport);

      // Set enabled protocols and cipher suites
      String[] enabledProtocols = properties.getStringArr(ClientProperty.TLS_PROTOCOLS);
      String[] enabledCipherSuites = properties.getStringArr(ClientProperty.TLS_CIPHERSUITES);
      socket.setEnabledProtocols(enabledProtocols);
      socket.setEnabledCipherSuites(enabledCipherSuites);


      // Set up auth unilateral or mutual
      boolean mutualAuth = properties.getBool(ClientProperty.TLS_MUTUAL_AUTH);
      socket.setNeedClientAuth(mutualAuth);
      socket.startHandshake();

      //MERDAS AQUI
      requestParam(socket, getTrustManagerFactory(properties), properties);

      //checks user command
      String command = args[0];
      switch (command.toLowerCase()) {
        case "create":
          break;
        case "list":
          break;
        case "new":
          break;
        case "all":
          break;
        case "send":
          break;
        case "recv":
          break;
        case "status":
          break;
        case "receipt":
          break;
      }


      System.out.print("Connected on port " + serverport + "\n");
    } catch (Exception e) {
      handleException(e, debugMode);
    } finally {
      System.exit(-1);
    }

  }

  private static void requestParam(SSLSocket sslSocket, TrustManagerFactory trustManagerFactory, CustomProperties props) throws IOException, InvalidFormatException {
    JsonObject requestData = new JsonObject();
    //vai explodir no server devido a nao ter o decode b64
    B4Helper b64 = new B4Helper();
    requestData.addProperty("type", b64.encode("params".getBytes()));
    requestData.addProperty("nonce", b64.encode(CryptUtil.randomBytes(16)));
    sslSocket.getOutputStream().write(requestData.toString().getBytes());

    //parses answer from server
    JsonReader input = new JsonReader(new SafeInputStreamReader(sslSocket.getInputStream()));
    JsonObject obj = GsonUtils.parseRequest(input);
    Gson g = new Gson();
    ParametersResponse response = g.fromJson(obj.toString(), ParametersResponse.class);
    X509Certificate certificate = (X509Certificate) sslSocket.getSession().getPeerCertificates()[0];

    //validate signature
    PublicKey publicKey = certificate.getPublicKey();
    //AEAHelper helper = new AEAHelper(props.getString())

  }

  private static void checkanotherUserDHkey(){
    //checks if x user has a in its ts/ks y users dh generated key
  }

  private static void saveAnotherUserDHkey(){

  }


  private static void handleException(Exception e, boolean debugMode) {
    boolean expected = false;

    if (e instanceof PropertyException)
      expected = true;

    if (expected) {
      System.err.println(e.getMessage());
    } else {
      System.err.println("CRITICAL ERROR.");
    }

    if (debugMode)
      e.printStackTrace();
  }

  private static TrustManagerFactory getTrustManagerFactory(CustomProperties properties) throws PropertyException, GeneralSecurityException, IOException {
    String trustStoreLoc = properties.getString(ClientProperty.TRUSTSTORE_LOC);
    String trustStorePass = properties.getString(ClientProperty.TRUSTSTORE_PASS);
    String trustStoreType = properties.getString(ClientProperty.TRUSTSTORE_TYPE);

    KeyStore trustStore = CryptUtil.loadKeystore(trustStoreLoc, trustStoreType, trustStorePass.toCharArray());

    TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("X509", CryptUtil.PROVIDER_TLS);
    trustManagerFactory.init(trustStore);

    return trustManagerFactory;
  }

  private static KeyStore getKeyStore(CustomProperties properties) throws PropertyException, GeneralSecurityException, IOException {
    String keyStoreLoc = properties.getString(ClientProperty.KEYSTORE_LOC);
    String keyStorePass = properties.getString(ClientProperty.KEYSTORE_PASS);
    String keyStoreType = properties.getString(ClientProperty.KEYSTORE_TYPE);

    return CryptUtil.loadKeystore(keyStoreLoc, keyStoreType, keyStorePass.toCharArray());
  }

  private static KeyManagerFactory getKeyManagerFactory(CustomProperties properties, KeyStore keyStore) throws PropertyException, GeneralSecurityException {
    String keyStorePass = properties.getString(ClientProperty.KEYSTORE_PASS);

    KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("X509", CryptUtil.PROVIDER_TLS);
    keyManagerFactory.init(keyStore, keyStorePass.toCharArray());

    return keyManagerFactory;
  }

  private static SSLContext buildSSLContext(CustomProperties properties, KeyStore keyStore) throws GeneralSecurityException, IOException, PropertyException {
    // Build default context for use with custom trust manager (OCSP) Extension
    KeyManagerFactory keyManagerFactory = getKeyManagerFactory(properties, keyStore);
    TrustManagerFactory trustManagerFactory = getTrustManagerFactory(properties);
    KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
    TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

    SSLContext sslContext = SSLContext.getInstance("TLS", CryptUtil.PROVIDER_TLS);
    sslContext.init(keyManagers, trustManagers, new SecureRandom());

    return sslContext;
  }

}
