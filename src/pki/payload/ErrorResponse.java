package pki.payload;

import shared.gson.GsonPayload;
import shared.http.HTTPStatus;

public class ErrorResponse extends GsonPayload {
  private String error;

  public ErrorResponse(HTTPStatus code, String error) {
    super(code);

    this.error = error;
  }
}
