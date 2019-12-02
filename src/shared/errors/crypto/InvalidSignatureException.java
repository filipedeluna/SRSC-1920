package shared.errors.crypto;

import java.security.GeneralSecurityException;

public final class InvalidSignatureException extends GeneralSecurityException {
  public InvalidSignatureException() {
    super("Certificate signature is invalid.");
  }
}
