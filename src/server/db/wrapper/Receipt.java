package server.db.wrapper;

import java.io.Serializable;

public final class Receipt implements Serializable {
  public int messageId;
  public String date;
  public String signature;
  public int sender_id;

  public Receipt() {}

  public Receipt(int messageId, String date, String signature) {
    this.messageId = messageId;
    this.date = date;
    this.signature = signature;
  }

  public Receipt(int message_id, int sender_id, String date, String signature) {
    this.messageId = message_id;
    this.date = date;
    this.signature = signature;
    this.sender_id = sender_id;
  }
}
