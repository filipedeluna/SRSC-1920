package shared.response;

import com.google.gson.Gson;
import shared.http.HTTPStatus;
import shared.http.HTTPStatusPair;

abstract class GsonResponse {
  private HTTPStatusPair status;

  GsonResponse(HTTPStatus status) {
    this.status = status.build();
  }

  public String json(Gson gson) {
    return gson.toJson(this);
  }
}
