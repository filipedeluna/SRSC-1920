package shared.http;

public class HTTPStatusPair {
  private int code;
  private String message;

  HTTPStatusPair(int code, String message) {
    this.code = code;
    this.message = message;
  }
}
