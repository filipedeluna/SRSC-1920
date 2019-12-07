package server.response;

public final class ParametersResponse extends OkResponseWithNonce {
  private final String parameters;
  private final String signature;

  public ParametersResponse(String nonce, String parameters, String signature) {
    super(nonce);
    this.parameters = parameters;
    this.signature = signature;
  }

  public String getParameters() {
    return parameters;
  }

  public String getSignature() {
    return signature;
  }
}
