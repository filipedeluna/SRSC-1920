package shared.errors.request;

import shared.http.HTTPStatus;

public final class InvalidRouteException extends RequestException {
  public InvalidRouteException() {
    super("Request route not found", HTTPStatus.NOT_FOUND);
  }
}
