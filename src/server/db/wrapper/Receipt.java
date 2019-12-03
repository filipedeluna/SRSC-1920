package server.db.wrapper;

public class Receipt {
  public int messageId;
  public String date;
  public String signature;

  public Receipt(int messageId, String date, String signature) {
    this.messageId = messageId;
    this.date = date;
    this.signature = signature;
  }
}
