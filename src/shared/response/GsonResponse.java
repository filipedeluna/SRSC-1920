package shared.response;

import com.google.gson.Gson;
import shared.http.HTTPStatus;
import shared.http.HTTPStatusPair;

import java.io.Serializable;

public class GsonResponse implements Serializable {
  private HTTPStatusPair status;

  GsonResponse() {}

  public GsonResponse(HTTPStatus status) {
    this.status = status.buildPair();
  }

  public String json(Gson gson) {
    return gson.toJson(this);
  }

  public HTTPStatusPair getStatus() {
    return status;
  }
}
