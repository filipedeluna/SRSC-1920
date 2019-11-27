package shared.errors.request;

import shared.http.HTTPStatus;
import shared.http.HTTPStatusPair;

public abstract class RequestException extends Exception {
  private HTTPStatus status;

  RequestException(String s, HTTPStatus status) {
    super("Request Exception: " + s + ".");

    this.status = status;
  }

  public HTTPStatus status() {
    return status;
  }
}
