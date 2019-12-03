package shared.errors.db;

import shared.http.HTTPStatus;

public final class FailedToInsertException extends DatabaseException {
  public FailedToInsertException() {
    super("Failed to insert entry in DB.", HTTPStatus.CONFLICT);
  }
}
