package shared.errors.db;

public abstract class DatabaseException extends Exception {
  DatabaseException(String text) {
    super("Database error: " + text);
  }
}
