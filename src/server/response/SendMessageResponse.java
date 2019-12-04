package server.response;

public final class SendMessageResponse extends OkResponseWithNonce {
  private int messageId;

  public SendMessageResponse(String nonce, int messageId) {
    super(nonce);
    this.messageId = messageId;
  }
}
