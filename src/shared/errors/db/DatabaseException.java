package shared.errors.db;

import shared.errors.IHTTPStatusException;
import shared.http.HTTPStatus;

public abstract class DatabaseException extends Exception implements IHTTPStatusException {
  private final HTTPStatus status;

  DatabaseException(String text, HTTPStatus status) {
    super("Database error: " + text);

    this.status = status;
  }

  public HTTPStatus status() {
    return status;
  }
}
