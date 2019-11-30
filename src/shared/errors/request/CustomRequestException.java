package shared.errors.request;

import shared.http.HTTPStatus;

public class CustomRequestException extends RequestException {
  public CustomRequestException(String text, HTTPStatus status) {
    super(text, status);
  }
}
