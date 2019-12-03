package server.db.wrapper;

public class Receipt {
  public int messageId;
  public int senderId;
  public String date;
  public String signature;

  public Receipt(int messageId, int senderId, String date, String signature) {
    this.messageId = messageId;
    this.senderId = senderId;
    this.date = date;
    this.signature = signature;
  }
}
