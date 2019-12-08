package server.response;

import shared.response.OKResponse;

abstract class OkResponseWithNonce extends OKResponse {
  private final String nonce;

  OkResponseWithNonce(String nonce) {
    this.nonce = nonce;
  }

  public String getNonce() {
    return nonce;
  }
}
