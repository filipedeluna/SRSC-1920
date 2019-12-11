package shared.wrappers;

import java.io.Serializable;

public final class Receipt implements Serializable {
  private int messageId;
  private int senderId;
  private String date;
  private String receiverSignature;

  public Receipt() {
  }

  public Receipt(int messageId, String date, String receiverSignature) {
    this.messageId = messageId;
    this.date = date;
    this.receiverSignature = receiverSignature;
  }

  public Receipt(int messageId, int senderId, String date, String receiverSignature) {
    this(messageId, date, receiverSignature);
    this.senderId = senderId;
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
