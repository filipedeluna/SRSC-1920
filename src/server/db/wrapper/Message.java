package server.db.wrapper;

import java.io.Serializable;

public final class Message implements Serializable {
  private int id;
  private int senderId;
  private int receiverId;
  private String text;
  private String attachmentData;
  private byte[] attachments;
  private String macHash;

  public Message() {
  }

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

  public int getId() {
    return id;
  }

  public int getSenderId() {
    return senderId;
  }

  public int getReceiverId() {
    return receiverId;
  }

  public String getText() {
    return text;
  }

  public String getAttachmentData() {
    return attachmentData;
  }

  public byte[] getAttachments() {
    return attachments;
  }

  public String getMacHash() {
    return macHash;
  }
}

