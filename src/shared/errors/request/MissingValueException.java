package shared.errors.request;

import shared.http.HTTPStatus;

public final class MissingValueException extends RequestException {
  public MissingValueException(String value) {
    super("Missing value \"" + value + "\" in request payload", HTTPStatus.BAD_REQUEST);
  }
}
