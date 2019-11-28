package shared.response;

import shared.http.HTTPStatus;

public abstract class OKResponse extends GsonResponse {
  public OKResponse() {
    super(HTTPStatus.OK);
  }
}
