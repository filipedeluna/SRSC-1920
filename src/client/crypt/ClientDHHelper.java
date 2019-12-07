package client.crypt;

import shared.utils.crypto.DHHelper;

import java.math.BigInteger;
import java.security.GeneralSecurityException;

public class ClientDHHelper extends DHHelper {
  private BigInteger p;
  private BigInteger g;

  public ClientDHHelper(String dhAlg, String hashAlg, int keySize, String p, String g) throws GeneralSecurityException {
    super(dhAlg, hashAlg, keySize);

    this.p = new BigInteger(p);
    this.g = new BigInteger(g);
  }

  public BigInteger getP() {
    return p;
  }

  public BigInteger getG() {
    return g;
  }
}
