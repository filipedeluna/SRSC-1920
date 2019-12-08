package shared.response.server;

import shared.response.OkResponseWithNonce;

public final class SendMessageResponse extends OkResponseWithNonce {
  private final int messageId;

  public SendMessageResponse(String nonce, int messageId) {
    super(nonce);
    this.messageId = messageId;
  }
}
