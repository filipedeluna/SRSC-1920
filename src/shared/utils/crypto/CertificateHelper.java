package shared.utils.crypto;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

public class CertificateHelper {
  private static final String PROVIDER = "BC";
  private static final String CERTIFICATE_FORMAT = "X.509";

  private CertificateFactory certificateFactory;

  public CertificateHelper() throws GeneralSecurityException {
    certificateFactory = CertificateFactory.getInstance(CERTIFICATE_FORMAT, PROVIDER);
  }

  public Certificate fromBytes(byte[] certBytes) throws CertificateException {
    return certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));
  }

  public Certificate fromFile(String file) throws CertificateException, FileNotFoundException {
    return certificateFactory.generateCertificate(new FileInputStream(file));
  }
}
