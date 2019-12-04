package shared.utils.crypto;

import shared.utils.CryptUtil;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

public final class HashHelper {
  private static final String PROVIDER = CryptUtil.PROVIDER;

  private MessageDigest messageDigest;

  public HashHelper(String algorithm) throws GeneralSecurityException {
    this.messageDigest = MessageDigest.getInstance(algorithm, PROVIDER);
  }

  public byte[] hash(byte[] data) {
    return messageDigest.digest(data);
  }

  public byte[] hashAndEncode(byte[] data) {
    return messageDigest.digest(data);
  }

  public boolean verifyHash(byte[] data, byte[] hash) {
    byte[] reHash = hash(data);

    return MessageDigest.isEqual(reHash, hash);
  }

  public int getHashSize() {
    return messageDigest.getDigestLength();
  }
}
