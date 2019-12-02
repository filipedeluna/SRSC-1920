package server.response;

import shared.response.OKResponse;

abstract class OkResponseWithNonce extends OKResponse {
  private String nonce;

  OkResponseWithNonce(String nonce) {
    this.nonce = nonce;
  }
}
