package shared.utils.crypto;

import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.crypto.engines.*;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.macs.GMac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import shared.utils.Utils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;

public final class MacHelper {
  private static final int GMAC_IV_SIZE = 12; // 96 bit - NIST Special Publication 800-38D
  private Mac mac;
  private int length;

  private RNDHelper rndHelper = new RNDHelper();

  public MacHelper(String macSpec) throws NoSuchAlgorithmException {
    // Check algorithm spec construction
    try {
      length = Integer.parseInt(macSpec.split(" ")[1]);
    } catch (NumberFormatException | NullPointerException e) {
      throw new NoSuchAlgorithmException("Invalid algorithm: " + macSpec);
    }

    // Check if algorithm is a HMAC or GMAC or CMAC construction
    switch (macSpec.split(" ")[0].toUpperCase()) {
      // CMACs-------------------------------
      case "AES-CMAC":
        mac = new CMac(new AESEngine(), length);
        break;
      case "BLOWFISH-CMAC":
        mac = new CMac(new BlowfishEngine(), length);
        break;
      case "DES-CMAC":
        mac = new CMac(new DESEngine(), length);
        break;
      case "THREEFISH-CMAC":
        try {
          int size = Integer.parseInt(macSpec.split(" ")[2]);
          mac = new CMac(new ThreefishEngine(size), length);
        } catch (NullPointerException | NumberFormatException e) {
          throw new NoSuchAlgorithmException("Invalid size for ThreeFish");
        }
        break;
      case "DESEDE-MAC":
        mac = new CMac(new DESedeEngine(), length);
        break;
      case "SEED-CMAC":
        mac = new CMac(new SEEDEngine(), length);
        break;
      // GMACs-------------------------------
      case "AES-GMAC":
        mac = new GMac(new GCMBlockCipher(new AESEngine()), length);
        break;
      case "CAT6-GMAC":
        mac = new GMac(new GCMBlockCipher(new CAST6Engine()), length);
        break;
      case "NOEKEON-GMAC":
        mac = new GMac(new GCMBlockCipher(new NoekeonEngine()), length);
        break;
      case "SEED-GMAC":
        mac = new GMac(new GCMBlockCipher(new SEEDEngine()), length);
        break;
      case "RC6-GMAC":
        mac = new GMac(new GCMBlockCipher(new RC6Engine()), length);
        break;
      case "ARIA-GMAC":
        mac = new GMac(new GCMBlockCipher(new ARIAEngine()), length);
        break;
      case "SHACAL2-GMAC":
        mac = new GMac(new GCMBlockCipher(new Shacal2Engine()), length);
        break;
      case "SM4-GMAC":
        mac = new GMac(new GCMBlockCipher(new SM4Engine()), length);
        break;
      // HMACs-------------------------------
      case "MD5-HMAC":
        mac = new HMac(new MD5Digest());
        break;
      case "SHA1-HMAC":
        mac = new HMac(new SHA1Digest());
        break;
      case "SHA2-HMAC":
        if (length == 256)
          mac = new HMac(new SHA256Digest());
        else if (length == 384)
          mac = new HMac(new SHA384Digest());
        else if (length == 512)
          mac = new HMac(new SHA512Digest());
        else
          throw new NoSuchAlgorithmException("Invalid size for SHA2.");
        break;
      case "SHA3-HMAC":
        mac = new HMac(new SHA3Digest(length));
        break;
      case "RIPEMD-HMAC":
        if (length == 128)
          mac = new HMac(new RIPEMD128Digest());
        else if (length == 160)
          mac = new HMac(new RIPEMD160Digest());
        else if (length == 256)
          mac = new HMac(new RIPEMD256Digest());
        else if (length == 320)
          mac = new HMac(new RIPEMD320Digest());
        else
          throw new NoSuchAlgorithmException("Invalid size for RIPEMD.");
        break;
      case "KECCAK-HMAC":
        mac = new HMac(new KeccakDigest(length));
        break;
      case "WHIRLPOOL-HMAC":
        mac = new HMac(new WhirlpoolDigest());
        break;
      case "DSTU7564-HMAC":
        mac = new HMac(new DSTU7564Digest(length));
        break;
      case "TIGER-HMAC":
        mac = new HMac(new TigerDigest());
        break;
      case "GOST3411-HMAC":
        mac = new HMac(new GOST3411Digest());
        break;
      case "SKEIN-HMAC":
        try {
          int size = Integer.parseInt(macSpec.split(" ")[2]);
          mac = new HMac(new SkeinDigest(length, size));
        } catch (NullPointerException | NumberFormatException e) {
          throw new NoSuchAlgorithmException("Invalid parameters for skein");
        }
        break;
      default:
        throw new NoSuchAlgorithmException("Invalid algorithm: " + macSpec);
    }
  }

  public boolean verifyHash(byte[] data, byte[] hash, Key key) throws NoSuchAlgorithmException {
    // Special case for gmac that needs to process the attached IV
    if (mac instanceof GMac)
      return verifyGmac(data, hash, key);

    byte[] reHashedBytes = hash(data, key);

    return MessageDigest.isEqual(reHashedBytes, hash);
  }

  private boolean verifyGmac(byte[] data, byte[] hash, Key key) {
    // Separate used iv from actual hash
    byte[] hashIv = Arrays.copyOfRange(hash, 0, GMAC_IV_SIZE);
    byte[] hashFixed = Arrays.copyOfRange(hash, GMAC_IV_SIZE, hash.length);

    mac.init(new ParametersWithIV(new KeyParameter(key.getEncoded()), hashIv));
    mac.update(data, 0, data.length);

    byte[] reHashedBytes = new byte[hash.length - GMAC_IV_SIZE];

    mac.doFinal(reHashedBytes, 0);

    return MessageDigest.isEqual(reHashedBytes, hashFixed);
  }

  public byte[] hash(byte[] data, Key key) throws NoSuchAlgorithmException {
    byte[] out;

    // Check the type of hash algorithm and hash data accordingly
    if (mac instanceof HMac || mac instanceof CMac) {
      mac.init(new KeyParameter(key.getEncoded()));
      mac.update(data, 0, data.length);

      out = new byte[length];

      mac.doFinal(out, 0);

      return out;
    }

    if (mac instanceof GMac) {
      byte[] iv = rndHelper.getBytes(GMAC_IV_SIZE, false);

      mac.init(new ParametersWithIV(new KeyParameter(key.getEncoded()), iv));
      mac.update(data, 0, data.length);

      out = new byte[length];

      mac.doFinal(out, 0);

      return Utils.joinByteArrays(iv, out);
    }

    throw new NoSuchAlgorithmException("No mac algorithm defined."); // Should never happen
  }

  public SecretKey getKeyFromBytes(byte[] keyBytes) {
    return new SecretKeySpec(keyBytes, "MAC"); //TODO Does this matter? Will it work?
  }

  public int getDigestSize() {
    if (mac instanceof HMac)
      return ((HMac) mac).getUnderlyingDigest().getDigestSize();

    return length / 8; // TODO does this make sense? It is the digest size always, supposedly
  }
}
