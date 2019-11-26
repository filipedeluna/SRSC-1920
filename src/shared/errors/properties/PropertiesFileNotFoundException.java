package shared.errors.properties;

public class PropertiesFileNotFoundException extends PropertiesException {
  public PropertiesFileNotFoundException(String path) {
    super("Properties file not found at path : " + path);
  }
}
