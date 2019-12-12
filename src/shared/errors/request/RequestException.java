package shared.errors.request;

import shared.errors.IHTTPStatusException;
import shared.http.HTTPStatus;

public abstract class RequestException extends Exception implements IHTTPStatusException {
  private final HTTPStatus status;

  RequestException(String s, HTTPStatus status) {
    super(s);

    this.status = status;
  }

  public HTTPStatus status() {
    return status;
  }
}
