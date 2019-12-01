package shared.utils.crypto;

import shared.errors.crypto.InvalidCertificateInfoException;
import sun.security.x509.*;

import javax.security.cert.CertificateEncodingException;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

public class CertificateHelper {
  private static final String PROVIDER = "BC";
  private static final String CERTIFICATE_FORMAT = "X.509";
  private static final String CERTIFICATE_KEY_ALG = "RSA";

  private static final long ONE_DAY = 24L * 60L * 60L * 1000L; // 1 year

  private CertificateFactory certFactory;
  private KeyFactory RSAKeyFactory;

  public CertificateHelper() throws GeneralSecurityException {
    certFactory = CertificateFactory.getInstance(CERTIFICATE_FORMAT, PROVIDER);
    RSAKeyFactory = KeyFactory.getInstance(CERTIFICATE_KEY_ALG, PROVIDER);
  }

  public PublicKey RSAKeyFromBytes(byte[] keyBytes) throws GeneralSecurityException {
    return RSAKeyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
  }

  public X509Certificate fromBytes(byte[] certBytes) throws GeneralSecurityException {
    return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certBytes));
  }

  public byte[] toBytes(X509Certificate certificate) throws GeneralSecurityException {
    return certificate.getTBSCertificate();
  }

  public X509Certificate fromFile(String file) throws GeneralSecurityException, FileNotFoundException {
    return (X509Certificate) certFactory.generateCertificate(new FileInputStream(file));
  }

  public X509Certificate signCertificate(X509Certificate cert, X509Certificate issuerCert, PrivateKey issuerPrivateKey, int validityDays) throws GeneralSecurityException {
    byte[] inCertBytes = cert.getTBSCertificate();
    X509CertInfo info = new X509CertInfo(inCertBytes);

    long currentTime = System.currentTimeMillis();

    try {
      info.set("validity", new CertificateValidity(new Date(currentTime), new Date(currentTime + ONE_DAY * validityDays)));
      info.set(X509CertInfo.ISSUER, issuerCert.getSubjectDN());
    } catch (IOException e) {
      throw new InvalidCertificateInfoException();
    }

    X509CertImpl outCert = new X509CertImpl(info);
    outCert.sign(issuerPrivateKey, issuerCert.getSigAlgName());

    return outCert;
  }

  public boolean validate(PublicKey publicKey, X509Certificate certificate) throws GeneralSecurityException {
    try {
      certificate.verify(publicKey, PROVIDER);
      return true;
    } catch (InvalidKeyException | SignatureException e) {
      return false;
    }
  }

  public X509Certificate convertJavaxCert(javax.security.cert.X509Certificate javaxCert) throws CertificateEncodingException, CertificateException {
    return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(javaxCert.getEncoded()));
  }

  public X509Certificate[] convertJavaxCerts(javax.security.cert.X509Certificate[] javaxCerts) throws CertificateEncodingException, CertificateException {
    X509Certificate[] newCerts = new X509Certificate[javaxCerts.length];

    for (int i = 0; i < javaxCerts.length; i++) {
      newCerts[i] = convertJavaxCert(javaxCerts[i]);
    }

    return newCerts;
  }
}
