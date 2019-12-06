package shared.errors.properties;

public abstract class PropertyException extends Exception {
  PropertyException(String s) {
    super("Property Exception: " + s + ".");
  }
}
