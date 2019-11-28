package shared.errors.db;

public final class FailedToInsertException extends DatabaseException {
  public FailedToInsertException() {
    super("Failed to insert entry in DB.");
  }
}
