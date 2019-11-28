package shared.errors.request;

import shared.http.HTTPStatus;

public class InvalidValueTypeException extends RequestException {
  public InvalidValueTypeException(String value, String expectedType) {
    super("Value \"" + value + "\" should be of type " + expectedType, HTTPStatus.BAD_REQUEST);
  }
}
