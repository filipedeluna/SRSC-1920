package shared.response.server;

import server.db.wrapper.Message;
import server.db.wrapper.Receipt;
import shared.response.OkResponseWithNonce;

import java.util.ArrayList;

public final class MessageReceiptsResponse extends OkResponseWithNonce {
  private final ArrayList<Receipt> receipts;
  private final Message message;

  public MessageReceiptsResponse(String nonce, Message message, ArrayList<Receipt> receipts) {
    super(nonce);
    this.receipts = receipts;
    this.message = message;
  }

  public ArrayList<Receipt> getReceipts() {
    return receipts;
  }

  public Message getMessage() {
    return message;
  }
}
