package shared.errors.request;

import shared.http.HTTPStatus;

public class InvalidRequestRouteException extends RequestException {
  public InvalidRequestRouteException() {
    super("Request route not found", HTTPStatus.NOT_FOUND);
  }
}
