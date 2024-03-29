package shared.http;

public final class HTTPStatusPair {
  private final int code;
  private final String message;

  HTTPStatusPair(int code, String message) {
    this.code = code;
    this.message = message;
  }

  public String getMessage() {
    return message;
  }

  public int getCode() {
    return code;
  }
}
