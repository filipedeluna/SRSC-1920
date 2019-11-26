package pki;

import shared.errors.properties.PropertiesException;
import shared.errors.properties.PropertiesFileErrorException;
import shared.errors.properties.PropertiesFileNotFoundException;
import shared.utils.PropertiesUtils;

import javax.net.ssl.SSLSocket;
import javax.xml.ws.Response;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.InetAddress;
import java.util.Properties;

class PKIServer {
  private static final String PROPS_PATH = "pki/pki.properties";


  public static void main(String[] args) {
    Properties props;

    try {
      props = PropertiesUtils.load(PROPS_PATH);
    } catch (PropertiesException e) {
      System.err.println(e.getMessage());
    }


      if (args.length < 1) {
        System.err.print("Usage: port\n");
        System.exit(1);
      }

      int port = Integer.parseInt(args[0]);

      try {
        ServerSocket s = new ServerSocket(port, 5, InetAddress.getByName("localhost"));
        System.out.print("Started server on port " + port + "\n");

        initServerThread(s);

      } catch (Exception e) {
        System.err.print("Cannot open socket: " + e);
        System.exit(-1);
      }

     catch (Exception e) {
      handleException(e);
    } finally {
      System.exit(-1);
    }
  }


  /*
     Utils
  */
  private static void initServerThread(ServerSocket s) {
    PKIServerControl registry = new PKIServerControl();

    SSLSocket c = s.accept();
    PKIServerActions handler = new PKIServerActions(c, registry);
    Thread t = new Thread(handler).start();
  }

  private static void handleException(Exception e) {
    boolean expected = false;

    if (e instanceof PropertiesException)
      expected = true;


    if (expected) {
      System.err.println(e.getMessage());
    } else {
      e.printStackTrace();
    }
  }
}
