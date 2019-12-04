package server.db.wrapper;

import java.io.Serializable;

public final class Message implements Serializable {
  public int id;
  public int senderId;
  public int receiverId;
  public String text;
  public String attachmentData;
  public byte[] attachments;
  public String macHash;

  public Message() {}

  public Message(int senderId, int receiverId, String text, String attachmentData, byte[] attachments, String macHash) {
    this.senderId = senderId;
    this.receiverId = receiverId;
    this.text = text;
    this.attachmentData = attachmentData;
    this.attachments = attachments;
    this.macHash = macHash;
  }

  public Message(int senderId, String text, String attachmentData, byte[] attachments) {
    this.senderId = senderId;
    this.text = text;
    this.attachmentData = attachmentData;
    this.attachments = attachments;
  }
}

