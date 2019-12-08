package client.utils;


public enum ClientRequest {
  LOGIN("login", 1),
  CREATE("create", 1),
  LIST("list",1),
  NEW("new", 1),
  ALL("all", 1),
  SEND("send", 1),
  RECEIVE("recv", 1),
  STATUS("status", 1),
  HELP("help", 1),
  EXIT("exit", 1);

  private final String val;
  private final int arguments;

  ClientRequest(String val, int arguments) {
    this.val = val;
    this.arguments = arguments;
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

  // Number of args not counting with args[0] (command)
  public int numberOfArgs() {
    return arguments;
  }
}

