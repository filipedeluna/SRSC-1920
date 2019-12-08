package client.utils;


public enum ClientRequest {
  LOGIN("login"),
  CREATE("create"),
  LIST("list"),
  NEW("new"),
  ALL("all"),
  SEND("send"),
  RECEIVE("recv"),
  STATUS("status"),
  HELP("help"),
  EXIT("exit");

  private final String val;

  ClientRequest(String val) {
    this.val = val;
  }

  public static ClientRequest fromString(String name) {
    for (ClientRequest request : values()) {
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
    return this != HELP && this != EXIT && this != LOGIN;
  }
}

