package shared.errors.db;

import shared.http.HTTPStatus;

public final class FailedToUpdateException extends DatabaseException {
  public FailedToUpdateException() {
    super("Failed to update entry in DB.", HTTPStatus.NOT_FOUND);
  }
}
