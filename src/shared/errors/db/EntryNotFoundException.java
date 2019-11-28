package shared.errors.db;

public final class EntryNotFoundException extends DatabaseException {
  public EntryNotFoundException() {
    super("Failed find entry in DB.");
  }
}
