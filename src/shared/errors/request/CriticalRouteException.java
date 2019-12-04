package shared.errors.request;

import shared.http.HTTPStatus;

public final class CriticalRouteException extends RequestException {
  public CriticalRouteException() {
    super("Critical server error, operation aborted", HTTPStatus.INTERNAL_SERVER_ERROR);
  }
}
