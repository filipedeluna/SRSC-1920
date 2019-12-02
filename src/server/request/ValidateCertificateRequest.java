package server.request;

import shared.request.GsonRequest;

public class ValidateCertificateRequest extends GsonRequest {
  private String serialNumber;

  public ValidateCertificateRequest(String serialNumber) {
    super("validate");
    this.serialNumber = serialNumber;
  }
}
