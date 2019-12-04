package server.response;

import server.db.wrapper.Message;
import server.db.wrapper.Receipt;

import java.util.ArrayList;

public class MessageReceiptsResponse extends OkResponseWithNonce {
  private ArrayList<Receipt> receipts;
  private Message message;

  public MessageReceiptsResponse(String nonce, Message message, ArrayList<Receipt> receipts) {
    super(nonce);
    this.receipts = receipts;
    this.message = message;
  }
}
