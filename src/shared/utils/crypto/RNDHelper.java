package shared.utils.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Base64.Encoder;

public final class RNDHelper {
  // NIST SP800-90A suggests 440 bits for SHA1 and SHA-256 seed
  // And 888 bits for SHA-384 and 512
  private static final int MAX_USES = 50; // Max uses before reseed
  private static final int SEED_SIZE = 111; // 888bits

  private final Encoder stringifier;
  private SecureRandom strongRandom; // dev/random -> Blocking
  private SecureRandom weakRandom;// dev/urandom -> Non Blocking

  private int strongUses;
  private int weakUses;

  // Use the stronger implementation by default.
  // Although slower, in a small setting, it should
  // be a better option as the overhead shouldnt matter much
  public RNDHelper() throws NoSuchAlgorithmException {
    strongRandom = SecureRandom.getInstanceStrong();
    weakRandom = new SecureRandom();

    stringifier = Base64.getEncoder().withoutPadding();
  }

  // Random Base64 string of size, cut because base64 adds characters
  public String getString(int size, boolean strong) {
    byte[] randomBytes = getBytes(size, strong);

    return stringifier.encodeToString(randomBytes).substring(0, size - 1);
  }

  public byte[] getBytes(int size, boolean strong) {
    checkUses(strong);

    byte[] randomBytes = new byte[size];
    chooseRandom(strong).nextBytes(randomBytes);

    return randomBytes;
  }

  public int getInt(boolean strong) {
    checkUses(strong);

    return chooseRandom(strong).nextInt();
  }

  public float getFloat(boolean strong) {
    checkUses(strong);

    return chooseRandom(strong).nextFloat();
  }

  public long getLong(boolean strong) {
    checkUses(strong);

    return chooseRandom(strong).nextLong();
  }

  private SecureRandom chooseRandom(boolean strong) {
    if (strong)
      strongUses++;
    else
      weakUses++;

    return strong ? strongRandom : weakRandom;
  }

  // Check number of seeds used to reseed
  // periodically, avoiding cryptoanalysis attacks
  // to the random generation algorithm
  // On linux, dev/random should seed itself and make
  // seedings virtually useless. But with a SHA instance,
  // it can be quite useful. The implementation will be left
  // for educational and testing purposes.
  private void checkUses(boolean strong) {
    // Always generate seeds with the strong random
    if (strongUses == MAX_USES) {
      strongRandom.setSeed(strongRandom.generateSeed(SEED_SIZE));
      strongUses = 0;
    }

    if (weakUses == MAX_USES) {
      weakRandom.setSeed(strongRandom.generateSeed(SEED_SIZE));
      weakUses = 0;
    }
  }
}
