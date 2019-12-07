package client.cache;

public class MessageCacheEntry extends CacheEntry {
  private int senderId;
  private byte[] text;
  private byte[] attachmentData;
  private byte[] attachments;
  private byte[] cipherIV;

  // All the entries are still encrypted but already decoded
  public MessageCacheEntry(int senderId, byte[] text, byte[] attachmentData, byte[] attachments, byte[] cipherIV) {
    this.senderId = senderId;
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
