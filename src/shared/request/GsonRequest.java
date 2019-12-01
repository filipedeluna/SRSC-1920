package shared.request;

import com.google.gson.Gson;

public abstract class GsonRequest {
  private String type;

  public GsonRequest(String type) {
    this.type = type;
  }

  public String json(Gson gson) {
    return gson.toJson(this);
  }

  public String getType() {
    return type;
  }
}
