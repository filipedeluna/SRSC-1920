package server.errors.parameters;

public final class DuplicateParameterException extends ParameterException {
  public DuplicateParameterException(String parameter) {
    super("Parameter " + parameter + " was inserted twice");
  }
}
