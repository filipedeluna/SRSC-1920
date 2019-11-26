package shared.errors.properties;

public class PropertiesFileErrorException extends PropertiesException {
  public PropertiesFileErrorException(String path) {
    super("Failed to read properties file at path: " + path);
  }
}
