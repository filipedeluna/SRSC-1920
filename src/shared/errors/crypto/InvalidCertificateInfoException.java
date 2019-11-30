package shared.errors.crypto;

import java.security.GeneralSecurityException;

public final class InvalidCertificateInfoException extends GeneralSecurityException {
  public InvalidCertificateInfoException() {
    super("Certificate info is invalid");
  }
}
