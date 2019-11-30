package shared.errors;

import shared.http.HTTPStatus;

public interface IHTTPStatusException {
  HTTPStatus status();
}
