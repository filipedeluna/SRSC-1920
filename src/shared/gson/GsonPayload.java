package shared.gson;

import com.google.gson.Gson;
import shared.http.HTTPStatus;
import shared.http.HTTPStatusPair;

public abstract class GsonPayload {
  private HTTPStatusPair status;

  public GsonPayload(HTTPStatus status) {
    this.status = status.build();
  }

  public String json(Gson gson) {
    return gson.toJson(this);
  }
}
