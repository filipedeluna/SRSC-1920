package shared.errors.properties;

public class InvalidPropertyTypeException extends PropertyException {
  public InvalidPropertyTypeException(String propName, String wrongType) {
    super("Property " + propName + " is not of type " + wrongType);
  }
}
