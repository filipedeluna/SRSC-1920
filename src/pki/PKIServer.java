package pki;

import pki.props.PKIProperties;
import pki.props.PKIProperty;
import shared.errors.properties.PropertyException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.IOException;

class PKIServer {
  private static final String PROPS_PATH = "pki/props/pki.properties";
  private static final String PROVIDER = "BC";

  public static void main(String[] args) {
    // Get properties from file
    PKIProperties props = null;
    // initial props
    boolean debugMode = false;

    try {
      props = new PKIProperties(PROPS_PATH);

      debugMode = props.getBoolean(PKIProperty.DEBUG);
    } catch (PropertyException e) {
      System.err.println(e.getMessage());
      System.exit(-1);
    }

    // Start main thread
    try {
      int port = props.getInt(PKIProperty.PORT);

      SSLContext sslContext = SSLContext.getInstance("TLS", PROVIDER);
      SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();

      SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(port);

      String[] enabledProtocols = props.getStringArray(PKIProperty.PROTOCOLS);
      String[] enabledCipherSuites = props.getStringArray(PKIProperty.CIPHERSUITES);

      serverSocket.setEnabledProtocols(enabledProtocols);
      serverSocket.setEnabledCipherSuites(enabledCipherSuites);

      System.out.print("Started server on port " + port + "\n");

      initServerThread(serverSocket);
    } catch (Exception e) {
      handleException(e, debugMode);
    } finally {
      System.exit(-1);
    }
  }

  /*
     Utils
  */
  private static void initServerThread(SSLServerSocket sslServerSocket) throws IOException {
    PKIServerControl serverControl = new PKIServerControl();

    while (true) {
      SSLSocket sslClient = (SSLSocket) sslServerSocket.accept();

      PKIServerResources pkiServerResources = new PKIServerResources(sslClient, serverControl);
      Thread t = new Thread(pkiServerResources);

      t.start();
    }
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
}
