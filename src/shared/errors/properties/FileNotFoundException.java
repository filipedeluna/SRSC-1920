package shared.errors.properties;

public final class FileNotFoundException extends PropertyException {
  public FileNotFoundException(String path) {
    super("Properties file not found at path : " + path);
  }
}
