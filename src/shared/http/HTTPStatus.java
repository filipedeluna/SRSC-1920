package shared.http;

import shared.response.ErrorResponse;

public enum HTTPStatus {
  OK(200, "OK"),

  BAD_REQUEST(400, "BAD REQUEST"),
  UNAUTHORIZED(401, "UNAUTHORIZED"),
  FORBIDDEN(403, "FORBIDDEN"),
  NOT_FOUND(404, "NOT FOUND"),
  CONFLICT(409, "CONFLICT"),

  INTERNAL_SERVER_ERROR(500, "INTERNAL_SERVER_ERROR");

  private final int code;
  private final String message;

  HTTPStatus(int code, String message) {
    this.code = code;
    this.message = message;
  }

  public int code() {
    return code;
  }

  public String message() {
    return message;
  }

  public HTTPStatusPair buildPair() {
    return new HTTPStatusPair(code, message);
  }

  public ErrorResponse buildErrorResponse() {
    return new ErrorResponse(this, message);
  }

  public ErrorResponse buildErrorResponse(String message) {
    return new ErrorResponse(this, message);
  }
}
