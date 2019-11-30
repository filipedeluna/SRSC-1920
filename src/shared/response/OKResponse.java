package shared.response;

import shared.http.HTTPStatus;

public class OKResponse extends GsonResponse {
  public OKResponse() {
    super(HTTPStatus.OK);
  }
}
