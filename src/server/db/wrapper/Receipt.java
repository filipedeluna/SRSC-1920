package server.db.wrapper;

import java.io.Serializable;

public final class Receipt implements Serializable {
  private int messageId;
  private String date;
  private String receiverSignature;

  public Receipt() {}

  public Receipt(int messageId, String date, String receiverSignature) {
    this.messageId = messageId;
    this.date = date;
    this.receiverSignature = receiverSignature;
  }

  public int getMessageId() {
    return messageId;
  }

  public String getDate() {
    return date;
  }

  public String getReceiverSignature() {
    return receiverSignature;
  }
}
