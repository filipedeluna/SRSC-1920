package pki.responses;

import shared.response.OKResponse;

public final class ValidateResponse extends OKResponse {
  private final String valid;

  public ValidateResponse(boolean validation) {
    this.valid = String.valueOf(validation);
  }
}
