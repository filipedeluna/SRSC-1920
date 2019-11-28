package shared.errors.properties;

public class FileErrorException extends PropertyException {
  public FileErrorException(String path) {
    super("Failed to read properties file at path: " + path);
  }
}
