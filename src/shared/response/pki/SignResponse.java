package shared.response.pki;

import shared.response.OKResponse;

public final class SignResponse extends OKResponse {
  private final String certificate;

  public SignResponse(String certificate) {
    this.certificate = certificate;
  }

  public String getCertificate() {
    return certificate;
  }
}
