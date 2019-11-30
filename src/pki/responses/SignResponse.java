package pki.responses;

import shared.response.OKResponse;

public class SignResponse extends OKResponse {
  private String certificate;

  public SignResponse(String certificate) {
    this.certificate = certificate;
  }

  public String getCertificate() {
    return certificate;
  }
}
