package pki;

import pki.db.PKIDatabaseDriver;
import pki.props.PKIProperty;
import shared.errors.properties.InvalidValueException;
import shared.errors.properties.PropertyException;
import shared.utils.crypto.KSHelper;
import shared.utils.properties.CustomProperties;

import javax.net.ssl.*;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

final class PKIServer {
  private static final String PROPS_PATH = "src/pki/props/pki.properties";

  @SuppressWarnings("InfiniteLoopStatement")
  public static void main(String[] args) {
    System.setProperty("java.net.preferIPv4Stack", "true");

    CustomProperties props = null;
    Logger logger = null;
    boolean debugMode = false;

    try {
      props = new CustomProperties(PROPS_PATH);

      // Create Logger and add a file handler to defined file
      String logFile = props.getString(PKIProperty.LOG_LOC);
      logger = Logger.getLogger("PKI Logger");
      logger.setLevel(Level.ALL);
      logger.addHandler(new FileHandler(logFile, true));

      debugMode = props.getBool(PKIProperty.DEBUG);
    } catch (PropertyException e) {
      System.err.println(e.getMessage());
      System.exit(-1);
    } catch (IOException e) {
      System.err.println("Failed to initiate logger: " + e.getMessage());
    }

    // Start main thread
    try {
      // Create thread pool for clients
      int threadPoolSize = props.getInt(PKIProperty.THREAD_POOL_SIZE);

      if (!validateThreadCount(threadPoolSize))
        throw new InvalidValueException(PKIProperty.THREAD_POOL_SIZE.val());

      Executor executor = Executors.newFixedThreadPool(threadPoolSize);

      // Load Keystore
      KSHelper ksHelper = new KSHelper(
          props.getString(PKIProperty.KEYSTORE_LOC),
          props.getString(PKIProperty.KEYSTORE_TYPE),
          props.getString(PKIProperty.KEYSTORE_PASS).toCharArray(),
          false
      );

      // Initiate KMF
      KeyManagerFactory keyManagerFactory = ksHelper.getKeyManagerFactory();

      // Create SSL Socket and initialize server
      int port = props.getInt(PKIProperty.PORT);

      SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());

      SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
      SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(port);

      // Set enabled protocols and cipher suites
      String[] enabledProtocols = props.getStringArr(PKIProperty.TLS_PROTOCOLS);
      String[] enabledCipherSuites = props.getStringArr(PKIProperty.TLS_CIPHERSUITES);

      serverSocket.setEnabledProtocols(enabledProtocols);
      serverSocket.setEnabledCipherSuites(enabledCipherSuites);
      serverSocket.setNeedClientAuth(false); // Unilateral

      logger.log(Level.INFO, "Started server on port: " + port);
      System.out.print("Started pki server on port " + port + "\n");

      // Create db and initiate properties
      PKIDatabaseDriver db = new PKIDatabaseDriver(props.getString(PKIProperty.DATABASE_LOC));
      PKIServerProperties pkiServerProps = new PKIServerProperties(props, db, logger, ksHelper);

      // Client serving loop
      SSLSocket sslClient;

      while (true) {
        sslClient = (SSLSocket) serverSocket.accept();
        executor.execute(new Thread(new PKIServerResources(sslClient, pkiServerProps)));
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
      System.err.println("CRITICAL ERROR: " + e.getClass().getName());
    }

    if (debugMode)
      e.printStackTrace();
  }

  private static boolean validateThreadCount(int threadCount) {
    int totalThreads = Runtime.getRuntime().availableProcessors();

    // Keep threads between 0 < threads < CPUTOTAL
    return totalThreads > threadCount && threadCount > 0;
  }
}
