package shared.response;

public abstract class OkResponseWithNonce extends OKResponse {
  private final String nonce;

  public OkResponseWithNonce(String nonce) {
    this.nonce = nonce;
  }

  public String getNonce() {
    return nonce;
  }
}
