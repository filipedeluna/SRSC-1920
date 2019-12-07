package client.cache;

abstract class CacheEntry {
  protected long size;

  CacheEntry() {
  }

  public long getSize() {
    return size;
  }
}
