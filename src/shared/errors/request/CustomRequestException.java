package shared.errors.request;

import shared.http.HTTPStatus;

public final class CustomRequestException extends RequestException {
  public CustomRequestException(String text, HTTPStatus status) {
    super(text, status);
  }
}
