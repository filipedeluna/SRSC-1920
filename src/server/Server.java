package server;

import com.google.gson.Gson;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import server.crypt.CustomTrustManager;
import server.db.ServerDatabaseDriver;
import server.props.ServerProperty;
import shared.errors.properties.InvalidValueException;
import shared.errors.properties.PropertyException;
import shared.utils.CryptUtil;
import shared.utils.GsonUtils;
import shared.utils.crypto.B4Helper;
import shared.utils.properties.CustomProperties;

import javax.net.ssl.*;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.sun.xml.internal.ws.spi.db.BindingContextFactory.LOGGER;

final class Server {
  private static final String PROPS_PATH = "src/server/props/server.properties";

  @SuppressWarnings("InfiniteLoopStatement")
  public static void main(String[] args) {
    System.setProperty("java.net.preferIPv4Stack", "true");
    Security.addProvider(new BouncyCastleJsseProvider());

    CustomProperties properties = null;
    Logger logger = null;
    boolean debugMode = false;

    try {
      properties = new CustomProperties(PROPS_PATH);

      // Create Logger and add a file handler to defined file
      String logFile = properties.getString(ServerProperty.LOG_LOC);
      logger = Logger.getLogger("Server Logger");
      logger.addHandler(new FileHandler(logFile, true));

      debugMode = properties.getBool(ServerProperty.DEBUG);
    } catch (PropertyException e) {
      System.err.println(e.getMessage());
      System.exit(-1);
    } catch (IOException e) {
      System.err.println("Failed to initiate logger: " + e.getMessage());
    }

    // Start main thread
    try {
      // Create thread pool for clients
      int threadPoolSize = properties.getInt(ServerProperty.THREAD_POOL_SIZE);

      if (!validateThreadCount(threadPoolSize))
        throw new InvalidValueException(ServerProperty.THREAD_POOL_SIZE.val());

      Executor executor = Executors.newFixedThreadPool(threadPoolSize);

      // Get Keystore
      KeyStore keyStore = getKeyStore(properties);

      // Create SSL Socket
      int port = properties.getInt(ServerProperty.PORT);

      SSLContext sslContext = buildSSLContext(properties, keyStore);

      SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
      SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(port);

      // Set enabled protocols and cipher suites
      String[] enabledProtocols = properties.getStringArr(ServerProperty.TLS_PROTOCOLS);
      String[] enabledCipherSuites = properties.getStringArr(ServerProperty.TLS_CIPHERSUITES);

      serverSocket.setEnabledProtocols(enabledProtocols);
      serverSocket.setEnabledCipherSuites(enabledCipherSuites);

      // Set up auth unilateral or mutual
      boolean mutualAuth = properties.getBool(ServerProperty.TLS_MUTUAL_AUTH);
      serverSocket.setNeedClientAuth(mutualAuth);

      System.out.print("Started server on port " + port + "\n");

      // Build DB and create shared properties class
      String databaseLocation = properties.getString(ServerProperty.DATABASE_LOC);
      ServerDatabaseDriver db = new ServerDatabaseDriver(databaseLocation);

      ServerProperties props = new ServerProperties(properties, keyStore, db, logger);

      // Client serving loop
      SSLSocket sslClient;

      while (true) {
        sslClient = (SSLSocket) serverSocket.accept();
        executor.execute(new Thread(new ServerResources(sslClient, props)));
      }
    } catch (Exception e) {
      handleException(e, debugMode, logger);
    } finally {
      System.exit(-1);
    }
  }

  /*
    Utils
  */
  private static void handleException(Exception e, boolean debugMode, Logger logger) {
    boolean expected = false;

    if (e instanceof PropertyException)
      expected = true;

    if (expected) {
      System.err.println(e.getMessage());
      logger.log(Level.WARNING, e.getMessage());
    } else {
      logger.log(Level.SEVERE, e.getMessage());
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

  private static KeyManagerFactory getKeyManagerFactory(CustomProperties properties, KeyStore keyStore) throws PropertyException, GeneralSecurityException {
    String keyStorePass = properties.getString(ServerProperty.KEYSTORE_PASS);

    KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("X509", CryptUtil.PROVIDER_TLS);
    keyManagerFactory.init(keyStore, keyStorePass.toCharArray());

    return keyManagerFactory;
  }

  private static TrustManagerFactory getTrustManagerFactory(CustomProperties properties) throws PropertyException, GeneralSecurityException, IOException {
    String trustStoreLoc = properties.getString(ServerProperty.TRUSTSTORE_LOC);
    String trustStorePass = properties.getString(ServerProperty.TRUSTSTORE_PASS);
    String trustStoreType = properties.getString(ServerProperty.TRUSTSTORE_TYPE);

    KeyStore trustStore = CryptUtil.loadKeystore(trustStoreLoc, trustStoreType, trustStorePass.toCharArray());

    TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("X509", CryptUtil.PROVIDER_TLS);
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
    // Build default context for use with custom trust manager (OCSP) Extension
    KeyManagerFactory keyManagerFactory = getKeyManagerFactory(properties, keyStore);
    TrustManagerFactory trustManagerFactory = getTrustManagerFactory(properties);
    KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
    TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

    SSLContext defaultSSLContext = SSLContext.getInstance("TLS", CryptUtil.PROVIDER_TLS);
    defaultSSLContext.init(keyManagers, trustManagers, new SecureRandom());

    // Check if PKI is to be used, if not.. return regular socket
    if (!properties.getBool(ServerProperty.USE_PKI))
      return defaultSSLContext;

    // Build server context with custom trust manager
    TrustManager[] extendedTrustManagers = new TrustManager[trustManagers.length + 1];
    System.arraycopy(trustManagers, 0, extendedTrustManagers, 0, trustManagers.length);
    Gson gson = GsonUtils.buildGsonInstance();

    // Add custom trust manager to trust managers
    extendedTrustManagers[trustManagers.length] =
        new CustomTrustManager(properties, defaultSSLContext.getSocketFactory(), trustManagers, new B4Helper(), gson);

    SSLContext serverSSLContext = SSLContext.getInstance("TLS", CryptUtil.PROVIDER_TLS);
    serverSSLContext.init(keyManagers, extendedTrustManagers, new SecureRandom());

    return serverSSLContext;
  }
}
