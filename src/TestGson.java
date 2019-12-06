import shared.http.HTTPStatus;
import shared.http.HTTPStatusPair;

public class TestGson {

  private final HTTPStatusPair status;
  private final String error;

  public TestGson(String error) {
    this.status = HTTPStatus.FORBIDDEN.buildPair();
    this.error = error;
  }
}
