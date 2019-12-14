package shared.wrappers;

import java.io.Serializable;

public final class Receipt implements Serializable {
  private int messageId;
  private int senderId;
  private String date;
  private String receiverSignature;

  public Receipt() {
  }

  public Receipt(int messageId, int senderId, String date, String receiverSignature) {
    this.messageId = messageId;
    this.senderId = senderId;
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

  public int getSenderId() {
    return senderId;
  }
}
