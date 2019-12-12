package shared.utils.crypto.util;

import java.security.cert.X509Certificate;

public class CertificateEntry {
  private X509Certificate certificate;
  private long creationDate;

  public CertificateEntry(X509Certificate certificate) {
    this.certificate = certificate;
    creationDate = System.currentTimeMillis();
  }

  public X509Certificate getCertificate() {
    return certificate;
  }

  public boolean stillValid(long validity) {
    return creationDate + validity < System.currentTimeMillis();
  }
}
