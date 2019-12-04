package shared.errors.request;

import shared.http.HTTPStatus;

public final class InvalidFormatException extends RequestException {
  public InvalidFormatException() {
    super("Request is not a JSON object", HTTPStatus.BAD_REQUEST);
  }
}
