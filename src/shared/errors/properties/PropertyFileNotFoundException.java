package shared.errors.properties;

public class PropertyFileNotFoundException extends PropertyException {
  public PropertyFileNotFoundException(String path) {
    super("Properties file not found at path : " + path);
  }
}
