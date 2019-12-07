package server.response;

import server.db.wrapper.Message;

public final class ReceiveMessageResponse extends OkResponseWithNonce {
  private Message message;

  public ReceiveMessageResponse(String nonce, Message message) {
    super(nonce);
    this.message = message;
  }

  public Message getMessage() {
    return message;
  }
}
