package shared.utils.crypto;

import shared.utils.CryptUtil;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.*;

public class DHHelper {
  private static final String PROVIDER = CryptUtil.PROVIDER;

  private String dhAlg;
  private KeyPairGenerator keyPairGenerator;
  private MessageDigest hash;

  public DHHelper(String dhAlg, String hashAlg, BigInteger primeP, BigInteger primeG) throws GeneralSecurityException {
    this.dhAlg = dhAlg;

    this.keyPairGenerator = KeyPairGenerator.getInstance(dhAlg, PROVIDER);
    DHParameterSpec dhParams = new DHParameterSpec(primeP, primeG);
    keyPairGenerator.initialize(dhParams);

    this.hash = MessageDigest.getInstance(hashAlg, PROVIDER);
  }

  public KeyPair generateKeyPair() {
    return keyPairGenerator.generateKeyPair();
  }

  public byte[] generateSharedKey(PrivateKey aKey, PublicKey bKey) throws GeneralSecurityException {
    KeyAgreement keyAgreement = KeyAgreement.getInstance(dhAlg, PROVIDER);

    keyAgreement.init(aKey);
    keyAgreement.doPhase(bKey, true); // true - last phase

    return hash.digest(keyAgreement.generateSecret());
  }

  public static BigInteger generatePrime(int size) {
    return BigInteger.probablePrime(size, new SecureRandom());
  }
}
