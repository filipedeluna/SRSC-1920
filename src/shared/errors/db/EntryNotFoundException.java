package shared.errors.db;

import shared.http.HTTPStatus;

public final class EntryNotFoundException extends DatabaseException {
  public EntryNotFoundException() {
    super("Failed find entry in DB.", HTTPStatus.NOT_FOUND);
  }
}
