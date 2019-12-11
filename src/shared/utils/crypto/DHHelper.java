package shared.utils.crypto;

import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;

public class DHHelper {
  protected static final String PROVIDER = "BC";
  private AlgorithmParameterGenerator algParamsGenerator;
  private int keySize;
  private String dhAlg;

  public DHHelper(String dhAlg, int keySize) throws GeneralSecurityException {
    // This generator cannot be BC because BC is broken
    algParamsGenerator = AlgorithmParameterGenerator.getInstance(dhAlg);
    algParamsGenerator.init(keySize);

    this.keySize = keySize;
    this.dhAlg = dhAlg;
  }
  public DHParameterSpec generateParams() throws InvalidParameterSpecException {
    AlgorithmParameters algParams = algParamsGenerator.generateParameters();

    return algParams.getParameterSpec(DHParameterSpec.class);
  }

  public int getKeySize() {
    return keySize;
  }

  public String getAlgorithm() {
    return dhAlg;
  }
}
