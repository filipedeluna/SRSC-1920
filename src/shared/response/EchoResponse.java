package shared.response;

public class EchoResponse extends OKResponse {
  private String message;

  public EchoResponse(String message) {
    super();
    this.message = message;
  }

  public String getMessage() {
    return message;
  }
}
