package server.errors.parameters;

public abstract class ParameterException extends Exception {
  ParameterException(String s) {
    super("Parameter Exception: " + s + ".");
  }
}
