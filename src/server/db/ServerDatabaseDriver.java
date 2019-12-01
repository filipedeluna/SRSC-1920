package server.db;

import org.sqlite.JDBC;
import shared.errors.db.CriticalDatabaseException;
import shared.errors.db.DatabaseException;
import shared.errors.db.DuplicateEntryException;
import shared.errors.db.EntryNotFoundException;

import java.sql.*;

public final class ServerDatabaseDriver {
  private static final int ERR_UNIQUE_CONSTRAINT = 19;
  private static final int ERR_NOT_FOUND = 12;

  private Connection connection;
  private String filesPath;

  public ServerDatabaseDriver(String dbPath, String filesPath) throws CriticalDatabaseException {
    this.filesPath = filesPath;

    // Connect to file
    connection = connect(dbPath);

    // Create table if it does not exist
    createTables();
  }

  private Connection connect(String path) throws CriticalDatabaseException {
    try {
      DriverManager.registerDriver(new JDBC());
      return DriverManager.getConnection("jdbc:sqlite:" + path);
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  private void createTables() throws CriticalDatabaseException {
    try {
      String query =
          "CREATE TABLE IF NOT EXISTS entries (" +
              "serial_number   TEXT    NOT NULL UNIQUE, " +
              "revoked         INTEGER NOT NULL, " +
              "PRIMARY KEY (cert_hash)" +
              ");";

      connection.createStatement().execute(query);
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public void register(String serialNumber) throws DatabaseException, CriticalDatabaseException {
    try {
      String insertQuery = "INSERT INTO entries (serial_number, revoked) VALUES (?, 0);";

      PreparedStatement ps = connection.prepareStatement(insertQuery);
      ps.setString(1, serialNumber);

      ps.executeUpdate();
    } catch (SQLException e) {
      if (e.getErrorCode() == ERR_UNIQUE_CONSTRAINT)
        throw new DuplicateEntryException();

      throw new CriticalDatabaseException(e);
    }
  }

  public boolean isValid(String serialNumber) throws CriticalDatabaseException {
    try {
      String selectUser = "SELECT * FROM entries WHERE serial_number = ? AND revoked = 0;";

      PreparedStatement ps = connection.prepareStatement(selectUser);
      ps.setString(1, serialNumber);

      ResultSet rs = ps.executeQuery();
      return rs.next();
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public void revoke(String serialNumber) throws DatabaseException, CriticalDatabaseException {
    try {
      String selectUser = "UPDATE entries SET revoked = 1 WHERE serial_number = ?;";

      PreparedStatement ps = connection.prepareStatement(selectUser);
      ps.setString(1, serialNumber);

      int updated = ps.executeUpdate();

      if (updated == 0)
        throw new EntryNotFoundException();

    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }
}
