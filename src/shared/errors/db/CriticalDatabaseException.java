package shared.errors.db;

import java.sql.SQLException;

public final class CriticalDatabaseException extends Exception {
  public CriticalDatabaseException(SQLException e) {
    super("Database critical error: CODE " + e.getErrorCode() + " - " + e.getMessage());
  }
}
