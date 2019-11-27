package shared.errors.properties;

public class PropertyNotFoundException extends PropertyException {
  public PropertyNotFoundException(String propName) {
    super("Property " + propName + " not set in file");
  }
}
