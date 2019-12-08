package shared.wrappers;

import java.io.Serializable;

public final class Message implements Serializable {
  private int id;
  private int senderId;
  private int receiverId;
  private String text;
  private String attachmentData;
  private byte[] attachments;
  private String cipherIV;
  private String senderSignature;

  public Message() {
  }

  public Message(int senderId, int receiverId, String text, String attachmentData, byte[] attachments, String cipherIV, String senderSignature) {
    this.senderId = senderId;
    this.receiverId = receiverId;
    this.text = text;
    this.attachmentData = attachmentData;
    this.attachments = attachments;
    this.cipherIV = cipherIV;
    this.senderSignature = senderSignature;
  }

  public Message(int senderId, String text, String attachmentData, byte[] attachments, String cipherIV, String senderSignature) {
    this.senderId = senderId;
    this.text = text;
    this.attachmentData = attachmentData;
    this.attachments = attachments;
    this.cipherIV = cipherIV;
    this.senderSignature = senderSignature;
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

  public String getIV() {
    return cipherIV;
  }

  public String getSenderSignature() {
    return senderSignature;
  }
}

