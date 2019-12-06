package server.db.wrapper;

import java.io.Serializable;

public final class Receipt implements Serializable {
  private int messageId;
  private String date;
  private String signature;

  public Receipt() {}

  public Receipt(int messageId, String date, String signature) {
    this.messageId = messageId;
    this.date = date;
    this.signature = signature;
  }

  public int getMessageId() {
    return messageId;
  }

  public String getDate() {
    return date;
  }

  public String getSignature() {
    return signature;
  }
}
