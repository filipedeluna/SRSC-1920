package server.response;

import shared.parameters.ServerParameterMap;

public final class ParametersResponse extends OkResponseWithNonce {
  private final ServerParameterMap parameters;

  public ParametersResponse(String nonce, ServerParameterMap parameters) {
    super(nonce);
    this.parameters = parameters;
  }

  public ServerParameterMap getParameters() {
    return parameters;
  }
}
