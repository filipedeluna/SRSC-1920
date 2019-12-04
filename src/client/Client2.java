package client;

import com.google.gson.JsonObject;
import pki.props.PKIProperty;
import shared.utils.crypto.AEAHelper;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.data;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.x509Certificate;

public class Client2 {
  private static final String PROPS_PATH = "/client/props/client.properties";
  private static final String PROVIDER = "BC";
  private static final String KSPW= "123asd";
  private static KeyStore keyStore;
  public static void main(String[] args) {

    try {

      KeyStore keyStore = KeyStore.getInstance("JCEKS");
      keyStore.load(new FileInputStream("//pki/crypt/pkiKeystore.jceks"), KSPW.toCharArray());
      KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509", PROVIDER);
      keyManagerFactory.init(keyStore, KSPW.toCharArray());


      BufferedReader bf = new BufferedReader(new FileReader(PROPS_PATH));
      //Gets all the client parameters from file, cyphersuit, tls version and server port to connect
      String tlscyphersuit = bf.readLine().split("=")[1];
      String tlsversion = bf.readLine().split("=")[1];
      String serverport = bf.readLine().split("=")[1];


      SSLContext sslContext = SSLContext.getInstance("TLS", PROVIDER);
      sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
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
      //SendSignToPKI(socket);


      System.out.print("Started connection with server " + serverport + "\n");
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (NoSuchProviderException | IOException e) {
      e.printStackTrace();
    } catch (KeyStoreException e) {
      e.printStackTrace();
    } catch (CertificateException e) {
      e.printStackTrace();
    } catch (UnrecoverableEntryException e) {
      //password mismatch to entry at keystore
      e.printStackTrace();
    } catch (GeneralSecurityException e) {
      e.printStackTrace();
    }


  }

  /*

  private static void SendSignToPKI(SSLSocket socket) throws GeneralSecurityException, IOException {
      Base64Helper b64 = new Base64Helper();
      String token = "123asd";
      JsonObject tosend = new JsonObject();
      tosend.addProperty("type", b64.encode("sign".getBytes()));
      token = b64.encode(token.getBytes());
      tosend.addProperty("token", token);
      KeyPair kp = AEAHelper.getKeyPair(keyStore, KSPW.toCharArray(), "client1keypair");
      tosend.addProperty("publicKey", b64.encode(kp.getPublic().toString().getBytes()));

      CertificateFactory fact = CertificateFactory.getInstance("X.509");
      X509Certificate cer = (X509Certificate) fact.generateCertificate(new FileInputStream("/client/crypt/client1cert.cer"));
      tosend.addProperty("certificate", b64.encode(cer.toString().getBytes()));
      socket.getOutputStream().write(tosend.getAsByte());
    //parse response


  }


   */
}
