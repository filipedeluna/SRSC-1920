package shared.response.server;

import shared.wrappers.Message;
import shared.response.OkResponseWithNonce;

public final class ReceiveMessageResponse extends OkResponseWithNonce {
  private final Message message;

  public ReceiveMessageResponse(String nonce, Message message) {
    super(nonce);
    this.message = message;
  }

  public Message getMessage() {
    return message;
  }
}
