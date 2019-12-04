package shared;


public enum ServerRequest {
  CREATE("create"),
  LIST("list"),
  NEW("new"),
  ALL("all"),
  SEND("send"),
  RECEIVE("recv"),
  RECEIPT("receipt"),
  STATUS("status"),
  PARAMS("params");

  private String val;

  ServerRequest(String val) {
    this.val = val;
  }

  public static ServerRequest fromString(String name) {
    for (ServerRequest request : values()) {
      if (request.val.equals(name.toLowerCase().trim()))
        return request;
    }

    // does not exist
    return null;
  }

  public String val() {
    return val;
  }

  public boolean needsNonce() {
    return this != ServerRequest.RECEIPT;
  }
}

