package shared.errors.request;

import shared.http.HTTPStatus;

public class InvalidRouteException extends RequestException {
  public InvalidRouteException() {
    super("Request route not found", HTTPStatus.NOT_FOUND);
  }
}
