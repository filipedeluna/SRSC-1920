package shared.errors.properties;

public final class InvalidValueException extends PropertyException {
  public InvalidValueException(String propName) {
    super("Invalid property value for property: " + propName);
  }
}
