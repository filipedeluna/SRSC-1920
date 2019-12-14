package client.cache;

public class MessageCacheEntry extends CacheEntry {
  private final int senderId;
  private final int receiverId;
  private final byte[] text;
  private final byte[] attachmentData;
  private final byte[] attachments;
  private final byte[] cipherIV;

  // All the entries are still encrypted but already decoded
  public MessageCacheEntry(int senderId, int receiverId, byte[] text, byte[] attachmentData, byte[] attachments, byte[] cipherIV) {
    this.senderId = senderId;
    this.receiverId = receiverId;
    this.text = text;
    this.attachmentData = attachmentData;
    this.attachments = attachments;
    this.cipherIV = cipherIV;

    // Get rough estimate of size
    size = 4 + text.length + attachmentData.length + attachments.length + cipherIV.length;
  }

  public int getSenderId() {
    return senderId;
  }

  public int getReceiverId() {
    return receiverId;
  }

  public byte[] getText() {
    return text;
  }

  public byte[] getAttachmentData() {
    return attachmentData;
  }

  public byte[] getAttachments() {
    return attachments;
  }

  public byte[] getCipherIV() {
    return cipherIV;
  }
}
