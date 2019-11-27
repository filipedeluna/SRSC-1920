package pki.props;

import shared.PropertyType;
import shared.errors.properties.InvalidPropertyTypeException;
import shared.errors.properties.InvalidPropertyValueException;
import shared.errors.properties.PropertyException;
import shared.errors.properties.PropertyNotFoundException;

import java.util.Properties;

public enum PKIProperty {
  // Add properties here
  PORT("port", PropertyType.INT),
  THREAD_POOL_SIZE("thread_pool_size", PropertyType.INT),

  DEBUG("debug", PropertyType.BOOL),

  CIPHERSUITES("port", PropertyType.STRING_ARRAY),
  PROTOCOLS("port", PropertyType.STRING_ARRAY);
  /////////////////////////////////////////////////

  private String val;
  private PropertyType type;

  PKIProperty(String val, PropertyType type) {
    this.val = val;
    this.type = type;
  }

  public String val() {
    return val;
  }

  PropertyType type() {
    return type;
  }
}
