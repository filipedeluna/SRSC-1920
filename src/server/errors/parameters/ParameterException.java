package server.errors.parameters;

public abstract class ParameterException extends Exception {
  public ParameterException(String s) {
    super("Parameter Exception: " + s + ".");
  }
}
