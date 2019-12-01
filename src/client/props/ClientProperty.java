package client.props;

import shared.utils.properties.CustomPropertyType;
import shared.utils.properties.ICustomProperty;

public enum ClientProperty implements ICustomProperty {
  // Add properties here
  PORT("port", CustomPropertyType.INT),

  CIPHERSUITES("ciphersuites", CustomPropertyType.STRING_ARRAY),
  PROTOCOLS("protocols", CustomPropertyType.STRING_ARRAY);
  /////////////////////////////////////////////////

  private String val;
  private CustomPropertyType type;

  ClientProperty(String val, CustomPropertyType type) {
    this.val = val;
    this.type = type;
  }

  public String val() {
    return val;
  }

  public CustomPropertyType type() {
    return type;
  }
}
