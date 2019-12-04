package shared.errors.db;

import shared.http.HTTPStatus;

public final class GenericItemNotFoundException extends DatabaseException {
  public GenericItemNotFoundException(String missingObject) {
    super("Failed to find " + missingObject + " entry in DB.", HTTPStatus.NOT_FOUND);
  }
}
