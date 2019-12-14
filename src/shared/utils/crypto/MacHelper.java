package shared.utils.crypto;

import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.crypto.engines.*;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.macs.GMac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public final class MacHelper {
  private CMac cmac;
  private GMac gmac;
  private HMac hmac;
  private int length;

  public MacHelper(String macSpec) throws NoSuchProviderException, NoSuchAlgorithmException {
    // Check if algorithm is a HMAC or GMAC or CMAC construction
    this.length = length;
    String macAlg;

    try {
      macAlg = macSpec.split(" ")[0].toUpperCase();
      length = Integer.parseInt(macSpec.split(" ")[1]);

    } catch (NumberFormatException | NullPointerException e) {
      throw new NoSuchAlgorithmException("Invalid algorithm: " + macSpec);

    }

    switch (macAlg) {
      // CMACs-------------------------------
      case "AES-CMAC":
        cmac = new CMac(new AESEngine(), length);
        break;
      case "BLOWFISH-CMAC":
        cmac = new CMac(new BlowfishEngine(), length);
        break;
      case "DES-CMAC":
        cmac = new CMac(new DESEngine(), length);
        break;
      case "THREEFISH-CMAC":
        cmac = new CMac(new ThreefishEngine(512), length);
        break;
      case "RC6C-MAC":
        cmac = new CMac(new RC6Engine(), length);
        break;
      case "IDEACMAC":
        cmac = new CMac(new IDEAEngine(), length);
        break;
      // GMACs-------------------------------
      case "AES-GMAC":
        gmac = new GMac(new GCMBlockCipher(new AESEngine()), length);
        break;
      case "BLOWFISH-GMAC":
        gmac = new GMac(new GCMBlockCipher(new BlowfishEngine()), length);
        break;
      case "DES-GMAC":
        gmac = new GMac(new GCMBlockCipher(new DESEngine()), length);
        break;
      case "THREEFISH-GMAC":
        gmac = new GMac(new GCMBlockCipher(new ThreefishEngine(512)), length);
        break;
      case "RC6-GMAC":
        gmac = new GMac(new GCMBlockCipher(new RC6Engine()), length);
        break;
      case "IDEA-GMAC":
        gmac = new GMac(new GCMBlockCipher(new IDEAEngine()), length);
        break;
      // HMACs-------------------------------
      case "MD5-HMAC":
        hmac = new HMac(new MD5Digest());
        break;
      case "SHA1-HMAC":
        hmac = new HMac(new SHA1Digest());
        break;
      case "SHA2-HMAC":
        if (length == 256)
          hmac = new HMac(new SHA256Digest());
        else if (length == 384)
          hmac = new HMac(new SHA384Digest());
        else if (length == 512)
          hmac = new HMac(new SHA512Digest());
        else
          throw new NoSuchAlgorithmException("Invalid size for SHA2.");
      case "SHA3-HMAC":
        hmac = new HMac(new SHA3Digest(length));
        break;
      default:
        throw new NoSuchAlgorithmException("Invalid algorithm: " + macSpec);
    }
  }

  public boolean verifyHash(byte[] data, byte[] hash, Key key) throws NoSuchAlgorithmException {
    byte[] reHashedBytes = hash(data, key);

    return MessageDigest.isEqual(reHashedBytes, hash);
  }

  public byte[] hash(byte[] data, Key key) throws NoSuchAlgorithmException {
    KeyParameter keyParameter = new KeyParameter(key.getEncoded());

    byte[] out;

    if (hmac != null) {
      hmac.init(keyParameter);
      hmac.update(data, 0, data.length);

      out = new byte[length];

      hmac.doFinal(out, 0);

      return out;
    }

    if (gmac != null) {
      gmac.init(keyParameter);
      gmac.update(data, 0, data.length);

      out = new byte[length];

      hmac.doFinal(out, 0);

      return out;
    }

    if (cmac != null) {
      cmac.init(keyParameter);
      cmac.update(data, 0, data.length);

      out = new byte[length];

      cmac.doFinal(out, 0);

      return out;
    }

    throw new NoSuchAlgorithmException("No mac algorithm defined."); // Should never happen
  }

  public SecretKey getKeyFromBytes(byte[] keyBytes) {
    return new SecretKeySpec(keyBytes, "MAC"); //TODO Does this matter? Will it work?
  }

  public int getMaxKeySize() {
    return length / 8; // TODO does this make sense? It is the digest size always, supposedly
  }
}
