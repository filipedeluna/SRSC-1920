package client.crypt;

import shared.utils.crypto.DHHelper;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class ClientDHHelper extends DHHelper {
  private MessageDigest hash;
  private KeyAgreement keyAgreement;
  private KeyPairGenerator keyPairGenerator;
  private KeyFactory keyFactory;

  private BigInteger p;
  private BigInteger g;

  public ClientDHHelper(String dhAlg, String hashAlg, int keySize, BigInteger p, BigInteger g) throws GeneralSecurityException {
    super(dhAlg, keySize);

    keyPairGenerator = KeyPairGenerator.getInstance(dhAlg, PROVIDER);
    keyFactory = KeyFactory.getInstance(dhAlg, PROVIDER);

    hash = MessageDigest.getInstance(hashAlg, PROVIDER);
    keyAgreement = KeyAgreement.getInstance(dhAlg, PROVIDER);

    this.p = p;
    this.g = g;
  }

  public byte[] genSharedKey(PrivateKey aKey, PublicKey bKey, int keySize) throws InvalidKeyException {
    keyAgreement.init(aKey);
    keyAgreement.doPhase(bKey, true); // true - last phase

    byte[] keyHash = hash.digest(keyAgreement.generateSecret());

    return Arrays.copyOfRange(keyHash, 0, keySize);
  }

  public BigInteger getP() {
    return p;
  }

  public BigInteger getG() {
    return g;
  }

  public String getHashAlgorithm() {
    return hash.getAlgorithm();
  }

  public KeyPair generateKeyPair(DHParameterSpec spec) throws InvalidAlgorithmParameterException {
    keyPairGenerator.initialize(spec);

    return keyPairGenerator.generateKeyPair();
  }

  public PublicKey generatePublicKey(KeySpec keySpec) throws InvalidKeySpecException {
    return keyFactory.generatePublic(keySpec);
  }
}
