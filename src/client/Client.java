package  client;

import pki.props.PKIProperty;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class Client {
  private static final String PROPS_PATH = "client/client.properties";
  private static final String PROVIDER = "BC";
  public static void main(String[] args) {

    try {
      BufferedReader bf = new BufferedReader(new FileReader(PROPS_PATH));
      //Gets all the client parameters from file, cyphersuit, tls version and server port to connect
      String tlscyphersuit = bf.readLine().split("=")[1];
      String tlsversion = bf.readLine().split("=")[1];
      String serverport = bf.readLine().split("=")[1];


      SSLContext sslContext = SSLContext.getInstance("TLS", PROVIDER);
      SSLSocketFactory factory= sslContext.getSocketFactory();
      SSLSocket socket = (SSLSocket)factory.createSocket("localhost", Integer.parseInt(serverport));

      String[] enabledProtocols = new String[1];
      enabledProtocols[0] = tlsversion;
      String[] enabledCipherSuites = new String[1];
      enabledCipherSuites[0] = tlscyphersuit;

      socket.setEnabledProtocols(enabledProtocols);
      socket.setEnabledCipherSuites(enabledCipherSuites);
      socket.startHandshake();
      //CORREU BEM canal seguro estabelecido
      socket.getOutputStream().write("hello world >(".getBytes());

      System.out.print("Started connection with server " + serverport + "\n");
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (NoSuchProviderException | IOException e) {
      e.printStackTrace();
    }
  }
}
