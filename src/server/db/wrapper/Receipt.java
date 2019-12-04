package server.db.wrapper;

import java.io.Serializable;

public final class Receipt implements Serializable {
  public int messageId;
  public String date;
  public String signature;

  public Receipt() {}

  public Receipt(int messageId, String date, String signature) {
    this.messageId = messageId;
    this.date = date;
    this.signature = signature;
  }
}
