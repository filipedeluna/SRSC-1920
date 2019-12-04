package server.response;

import server.db.wrapper.Message;

public class ReceiveMessageResponse extends OkResponseWithNonce {
  private Message message;

  public ReceiveMessageResponse(String nonce, Message message) {
    super(nonce);
    this.message = message;
  }
}