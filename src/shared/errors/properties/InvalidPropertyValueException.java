package shared.errors.properties;

public class InvalidPropertyValueException extends PropertyException {
  public InvalidPropertyValueException(String propName) {
    super("Invalid property value for property: " + propName);
  }
}
