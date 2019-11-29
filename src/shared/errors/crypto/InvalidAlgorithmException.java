package shared.errors.crypto;

import java.security.GeneralSecurityException;

public final class InvalidAlgorithmException extends GeneralSecurityException {
  public InvalidAlgorithmException(String cipher) {
    super("Unsupported Algorithm: " + cipher);
  }
}
