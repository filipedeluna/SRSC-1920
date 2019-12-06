package server.response;

import server.db.wrapper.Message;

public final class ReceiveMessageResponse extends OkResponseWithNonce {
  private final Message message;

  public ReceiveMessageResponse(String nonce, Message message) {
    super(nonce);
    this.message = message;
  }
}
