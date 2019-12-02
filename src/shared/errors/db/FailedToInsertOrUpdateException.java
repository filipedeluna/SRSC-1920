package shared.errors.db;

import shared.http.HTTPStatus;

public final class FailedToInsertOrUpdateException extends DatabaseException {
  public FailedToInsertOrUpdateException() {
    super("Failed to insert or update entry in DB.", HTTPStatus.NOT_FOUND);
  }
}
