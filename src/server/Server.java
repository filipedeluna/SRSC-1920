package server;

import com.google.gson.Gson;
import server.crypt.CustomTrustManager;
import server.db.ServerDatabaseDriver;
import server.props.ServerProperty;
import shared.errors.properties.InvalidValueException;
import shared.errors.properties.PropertyException;
import shared.utils.CryptUtil;
import shared.utils.GsonUtils;
import shared.utils.crypto.Base64Helper;
import shared.utils.properties.CustomProperties;

import javax.net.ssl.*;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

class Server {
  private static final String PROPS_PATH = "server/props/server.properties";
  private static final String PROVIDER = "BC";

  @SuppressWarnings("InfiniteLoopStatement")
  public static void main(String[] args) {

    // Get properties from file
    CustomProperties properties = null;
    // initial props
    boolean debugMode = false;

    try {
      properties = new CustomProperties(PROPS_PATH);

      debugMode = properties.getBoolean(ServerProperty.DEBUG);
    } catch (PropertyException e) {
      System.err.println(e.getMessage());
      System.exit(-1);
    }

    // Start main thread
    try {
      // Create thread pool for clients
      int threadPoolSize = properties.getInt(ServerProperty.THREAD_POOL_SIZE);

      if (validateThreadCount(threadPoolSize))
        throw new InvalidValueException(ServerProperty.THREAD_POOL_SIZE.val());

      Executor executor = Executors.newFixedThreadPool(threadPoolSize);

      // Set java properties and get Keystore
      setJavaProperties();
      KeyStore keyStore = getKeyStore(properties);

      // Create SSL Socket
      int port = properties.getInt(ServerProperty.PORT);

      SSLContext sslContext = buildSSLContext(properties, keyStore);

      SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
      SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(port);

      // Set enabled protocols and cipher suites
      String[] enabledProtocols = properties.getStringArray(ServerProperty.TLS_PROTOCOLS);
      String[] enabledCipherSuites = properties.getStringArray(ServerProperty.TLS_CIPHERSUITES);

      serverSocket.setEnabledProtocols(enabledProtocols);
      serverSocket.setEnabledCipherSuites(enabledCipherSuites);

      // Set up auth unilateral or mutual
      boolean mutualAuth = properties.getBoolean(ServerProperty.TLS_CIPHERSUITES);
      serverSocket.setNeedClientAuth(mutualAuth);

      System.out.print("Started server on port " + port + "\n");

      String databaseLocation = properties.getString(ServerProperty.DATABASE_LOC);
      String databaseFilesLocation = properties.getString(ServerProperty.DATABASE_FILES_LOC);
      ServerDatabaseDriver db = new ServerDatabaseDriver(databaseLocation, databaseFilesLocation);

      // Client serving loop
      while (true) {
        SSLSocket sslClient = (SSLSocket) serverSocket.accept();

        ServerResources serverResources = new ServerResources(sslClient, properties, keyStore, db, debugMode);
        executor.execute(new Thread(serverResources));
      }
    } catch (Exception e) {
      handleException(e, debugMode);
    } finally {
      System.exit(-1);
    }
  }

  /*
    Utils
  */
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

  private static boolean validateThreadCount(int threadCount) {
    int totalThreads = Runtime.getRuntime().availableProcessors();

    // Keep threads between 0 < threads < CPUTOTAL
    return totalThreads > threadCount && threadCount > 0;
  }

  private static void setJavaProperties() {
    System.setProperty("java.net.preferIPv4Stack", "true");
  }

  private static KeyManagerFactory getKeyManagerFactory(CustomProperties properties, KeyStore keyStore) throws PropertyException, GeneralSecurityException, IOException {
    String keyStorePass = properties.getString(ServerProperty.KEYSTORE_PASS);

    KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509", PROVIDER);
    keyManagerFactory.init(keyStore, keyStorePass.toCharArray());

    return keyManagerFactory;
  }

  private static TrustManagerFactory getTrustManagerFactory(CustomProperties properties) throws PropertyException, GeneralSecurityException, IOException {
    String trustStoreLoc = properties.getString(ServerProperty.TRUSTSTORE_LOC);
    String trustStorePass = properties.getString(ServerProperty.TRUSTSTORE_PASS);
    String trustStoreType = properties.getString(ServerProperty.TRUSTSTORE_TYPE);

    KeyStore trustStore = CryptUtil.loadKeystore(trustStoreLoc, trustStoreType, trustStorePass.toCharArray());

    TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509", PROVIDER);
    trustManagerFactory.init(trustStore);

    return trustManagerFactory;
  }

  private static KeyStore getKeyStore(CustomProperties properties) throws PropertyException, GeneralSecurityException, IOException {
    String keyStoreLoc = properties.getString(ServerProperty.KEYSTORE_LOC);
    String keyStorePass = properties.getString(ServerProperty.KEYSTORE_PASS);
    String keyStoreType = properties.getString(ServerProperty.KEYSTORE_TYPE);

    return CryptUtil.loadKeystore(keyStoreLoc, keyStoreType, keyStorePass.toCharArray());
  }

  private static SSLContext buildSSLContext(CustomProperties properties, KeyStore keyStore) throws GeneralSecurityException, IOException, PropertyException {
    SSLContext defaultSSLContext = SSLContext.getInstance("TLS", PROVIDER);

    // Build default context for use with custom trust manager (OCSP) Extension
    KeyManagerFactory keyManagerFactory = getKeyManagerFactory(properties, keyStore);
    TrustManagerFactory trustManagerFactory = getTrustManagerFactory(properties);
    KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
    TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

    defaultSSLContext.init(keyManagers, trustManagers, new SecureRandom());

    // Build server context with custom trust manager
    TrustManager[] extendedTrustManagers = new TrustManager[trustManagers.length + 1];
    System.arraycopy(trustManagers, 0, extendedTrustManagers, 0, trustManagers.length);
    Base64Helper base64Helper = new Base64Helper();
    Gson gson = GsonUtils.buildGsonInstance();
    extendedTrustManagers[trustManagers.length] =
        new CustomTrustManager(properties, defaultSSLContext.getSocketFactory(), base64Helper, gson);

    SSLContext serverSSLContext = SSLContext.getInstance("TLS", PROVIDER);
    serverSSLContext.init(keyManagers, extendedTrustManagers, new SecureRandom());

    return serverSSLContext;
  }
}
