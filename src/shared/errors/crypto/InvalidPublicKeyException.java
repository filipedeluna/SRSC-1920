package shared.errors.crypto;

import java.security.GeneralSecurityException;

public final class InvalidPublicKeyException extends GeneralSecurityException {
  public InvalidPublicKeyException() {
    super("Key obtained from keystore is not a public or private key");
  }
}
