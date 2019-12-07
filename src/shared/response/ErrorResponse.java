package shared.response;

import shared.http.HTTPStatus;

public class ErrorResponse extends GsonResponse {
  private final String error;

  public ErrorResponse(HTTPStatus code, String error) {
    super(code);

    this.error = error;
  }

  public String getError() {
    return error;
  }
}
