package shared.errors.properties;

public class PropertyFileErrorException extends PropertyException {
  public PropertyFileErrorException(String path) {
    super("Failed to read properties file at path: " + path);
  }
}
