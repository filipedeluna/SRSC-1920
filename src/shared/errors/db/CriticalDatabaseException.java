package shared.errors.db;

import server.errors.parameters.ParameterException;

import java.sql.SQLException;

public final class CriticalDatabaseException extends Exception {
  public CriticalDatabaseException(SQLException e) {
    super("Database critical error: CODE " + e.getErrorCode() + " - " + e.getMessage());
  }

  public CriticalDatabaseException(ParameterException e) {
    super("Database critical error: " + e.getMessage());
  }
}
