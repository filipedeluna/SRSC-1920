package shared.errors.db;

public final class FailedToDeleteException extends DatabaseException {
  public FailedToDeleteException() {
    super("Failed to delete entry in DB.");
  }
}
