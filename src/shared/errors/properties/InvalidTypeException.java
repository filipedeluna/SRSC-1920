package shared.errors.properties;

public final class InvalidTypeException extends PropertyException {
  public InvalidTypeException(String propName, String wrongType) {
    super("Property " + propName + " is not of type " + wrongType);
  }
}
