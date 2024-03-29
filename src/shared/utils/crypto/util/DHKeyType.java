package shared.utils.crypto.util;

public enum DHKeyType {
  SEA("sea"),
  MAC("mac");

  private final String val;

  DHKeyType(String val) {
    this.val = val;
  }

  public String getVal() {
    return val;
  }
}
