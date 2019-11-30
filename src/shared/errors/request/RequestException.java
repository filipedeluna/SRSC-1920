package shared.errors.request;

import shared.errors.IHTTPStatusException;
import shared.http.HTTPStatus;

public abstract class RequestException extends Exception implements IHTTPStatusException {
  private HTTPStatus status;

  RequestException(String s, HTTPStatus status) {
    super("Request Exception: " + s + ".");

    this.status = status;
  }

  public HTTPStatus status() {
    return status;
  }
}
