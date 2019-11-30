package shared.utils.crypto;

import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Base64.Decoder;

public class Base64Helper {
  private Encoder encoder;
  private Decoder decoder;

  public Base64Helper() {
    this.decoder = Base64.getDecoder();
    this.encoder = Base64.getEncoder();
  }

  public String encode(byte[] bytes) {
    return encoder.encodeToString(bytes);
  }

  public byte[] decode(String string){
    return decoder.decode(string);
  }
}