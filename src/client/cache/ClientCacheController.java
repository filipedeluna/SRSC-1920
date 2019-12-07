package client.cache;

import java.util.HashMap;
import java.util.Map.Entry;

public final class ClientCacheController {
  private long maxSize;
  private long currentSize;

  // Entries are id - Object
  private HashMap<Integer, MessageCacheEntry> messageCache;
  private HashMap<Integer, UserCacheEntry> userCache;

  // Entries are id - uses, this why we can get an idea of what isnt being accessed
  // And prioritize what matters
  private HashMap<Integer, Integer> messageCacheAccesses;
  private HashMap<Integer, Integer> userCacheAccesses;

  // Very basic cache implementation that doesn't allow the
  // memory to get completely full of entries
  public ClientCacheController(long maxSize) {
    this.maxSize = maxSize;

    currentSize = 0;

    messageCache = new HashMap<>();
    messageCacheAccesses = new HashMap<>();
    userCache = new HashMap<>();
    userCacheAccesses = new HashMap<>();
  }

  public void addMessage(int messageId, MessageCacheEntry message) {
    messageCache.put(messageId, message);
    messageCacheAccesses.put(messageId, 0);

    manageCache();
  }

  public void addUser(int userId, UserCacheEntry user) {
    userCache.put(userId, user);
    userCacheAccesses.put(userId, 0);

    manageCache();
  }

  public MessageCacheEntry getMessage(int messageId) {
    addMessageAccess(messageId);

    return messageCache.get(messageId);
  }

  public UserCacheEntry getUser(int userId) {
    addUserAccess(userId);

    return userCache.get(userId);
  }

  // Free up memory if needed recursively
  // Not the smartest algorithm. but a little bit
  // better than a bluescreen
  private void manageCache() {
    // If below max size, everything is ok
    if (currentSize <= maxSize)
      return;

    int leastAccessedMessage = -1;
    int leastAccessedUser = -1;
    // Highly unlikely there will be these many accesses
    // Still, someone is free to try and send me the error log
    int leastAccessedMessageAccesses = Integer.MAX_VALUE;
    int leastAccessedUserAccesses = Integer.MAX_VALUE;

    // Cycle all messages
    for (Entry<Integer, Integer> message : messageCacheAccesses.entrySet()) {
      if (message.getValue() < leastAccessedMessageAccesses) {
        leastAccessedMessage = message.getKey();
        leastAccessedMessageAccesses = message.getValue();
      }
    }

    // Cycle all users
    for (Entry<Integer, Integer> user : userCacheAccesses.entrySet()) {
      if (user.getValue() < leastAccessedUserAccesses) {
        leastAccessedUser = user.getKey();
        leastAccessedUserAccesses = user.getValue();
      }
    }

    // Remove entry with least accesses
    if (leastAccessedMessageAccesses < leastAccessedUserAccesses)
      messageCache.remove(leastAccessedMessage);
    else
      userCache.remove(leastAccessedUser);

    // Check everything is alright again
    manageCache();
  }

  private void addUserAccess(int userId) {
    userCacheAccesses.put(userId, userCacheAccesses.get(userId) + 1);
  }

  private void addMessageAccess(int messageId) {
    messageCacheAccesses.put(messageId, messageCacheAccesses.get(messageId) + 1);
  }
}
