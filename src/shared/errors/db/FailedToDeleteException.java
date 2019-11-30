package shared.errors.db;

import shared.http.HTTPStatus;

public final class FailedToDeleteException extends DatabaseException {
  public FailedToDeleteException() {
    super("Failed to delete entry in DB.", HTTPStatus.NOT_FOUND);
  }
}
