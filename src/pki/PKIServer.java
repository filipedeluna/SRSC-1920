package pki;

import pki.props.PKIProperties;
import pki.props.PKIProperty;
import shared.errors.properties.InvalidValueException;
import shared.errors.properties.PropertyException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

class PKIServer {
  private static final String PROPS_PATH = "src/pki/props/pki.properties";
  private static final String PROVIDER = "BC";

  public static void main(String[] args) {
    // Get properties from file
    PKIProperties properties = null;
    // initial props
    boolean debugMode = false;

    try {
      properties = new PKIProperties(PROPS_PATH);

      debugMode = properties.getBoolean(PKIProperty.DEBUG);
    } catch (PropertyException e) {
      System.err.println(e.getMessage());
      System.exit(-1);
    }

    // Start main thread
    try {
      // Create thread pool for clients
      int threadPoolSize = properties.getInt(PKIProperty.THREAD_POOL_SIZE);

      if (validateThreadCount(threadPoolSize))
        throw new InvalidValueException(PKIProperty.THREAD_POOL_SIZE.val());

      Executor executor = Executors.newFixedThreadPool(threadPoolSize);

      // Create SSL Socket and initialize server
      int port = properties.getInt(PKIProperty.PORT);

      SSLContext sslContext = (SSLContext) SSLContext.getInstance("TLS");

      SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();

      SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(port);

      String[] enabledProtocols = properties.getStringArray(PKIProperty.PROTOCOLS);
      String[] enabledCipherSuites = properties.getStringArray(PKIProperty.CIPHERSUITES);

      serverSocket.setEnabledProtocols(enabledProtocols);
      serverSocket.setEnabledCipherSuites(enabledCipherSuites);

      System.out.print("Started server on port " + port + "\n");

      // Client serving loop
      while (true) {
        SSLSocket sslClient = (SSLSocket) serverSocket.accept();
        byte[] b = new byte[7000];
        sslClient.getInputStream().read(b);

        PKIServerResources pkiServerResources = new PKIServerResources(sslClient, properties, debugMode);
        executor.execute(new Thread(pkiServerResources));
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
}
