package shared.errors.properties;

public class FileNotFoundException extends PropertyException {
  public FileNotFoundException(String path) {
    super("Properties file not found at path : " + path);
  }
}
