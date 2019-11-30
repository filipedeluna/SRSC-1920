package shared.errors.db;

import shared.http.HTTPStatus;

public final class DuplicateEntryException extends DatabaseException {
  public DuplicateEntryException() {
    super("Failed to insert entry in DB.", HTTPStatus.CONFLICT);
  }
}
