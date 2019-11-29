package shared.errors.db;

public final class FailedToUpdateException extends DatabaseException {
  public FailedToUpdateException() {
    super("Failed to update entry in DB.");
  }
}
