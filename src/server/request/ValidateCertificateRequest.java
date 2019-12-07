package server.request;

import shared.request.GsonRequest;

public final class ValidateCertificateRequest extends GsonRequest {
  private final String certificate;

  public ValidateCertificateRequest(String certificate) {
    super("validate");
    this.certificate = certificate;
  }
}
