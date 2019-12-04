package pki.responses;

import shared.response.OKResponse;

public final class ValidateResponse extends OKResponse {
  private String valid;

  public ValidateResponse(boolean validation) {
    this.valid = String.valueOf(validation);
  }
}
