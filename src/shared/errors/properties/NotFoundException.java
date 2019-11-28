package shared.errors.properties;

public class NotFoundException extends PropertyException {
  public NotFoundException(String propName) {
    super("Property " + propName + " not set in file");
  }
}
