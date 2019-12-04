package server.errors.parameters;

public final class InvalidParameterOrderException extends ParameterException {
  public InvalidParameterOrderException() {
    super("Parameter order corrupted");
  }
}
