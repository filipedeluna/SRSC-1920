package shared.errors.properties;

public final class FileErrorException extends PropertyException {
  public FileErrorException(String path) {
    super("Failed to read properties file at path: " + path);
  }
}
