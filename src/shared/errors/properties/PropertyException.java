package shared.errors.properties;

public abstract class PropertyException extends Exception {
  public PropertyException(String s) {
    super("Property Exception: " + s + ".");
  }
}
