package shared.errors.properties;

public abstract class PropertiesException extends Exception {
  public PropertiesException(String s) {
    super("PropertiesException: " + s + ".");
  }
}
