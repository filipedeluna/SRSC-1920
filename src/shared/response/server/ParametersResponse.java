package shared.response.server;

import shared.parameters.ServerParameterMap;
import shared.response.OkResponseWithNonce;

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
