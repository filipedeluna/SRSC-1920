package shared.errors.properties;

public class InvalidTypeException extends PropertyException {
  public InvalidTypeException(String propName, String wrongType) {
    super("Property " + propName + " is not of type " + wrongType);
  }
}
