package client.utils;


public enum ClientCommands {
  CREATE("create"),
  LIST("list"),
  NEW("new"),
  ALL("all"),
  SEND("send"),
  RECEIVE("recv"),
  RECEIPT("receipt"),
  STATUS("status"),
  PARAMS("params"),
  HELP("help"),
  EXIT("exit");

  private final String val;

  ClientCommands(String val) {
    this.val = val;
  }

  public static ClientCommands fromString(String name) {
    for (ClientCommands request : values()) {
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
    return this != ClientCommands.RECEIPT;
  }
}

