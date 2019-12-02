package server.db;

import org.sqlite.JDBC;
import shared.errors.db.*;

import java.sql.*;
import java.util.HashMap;
import java.util.Map;

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
    // createTables();
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
              "PRIMARY KEY (serial_number)" +
              ");";

      connection.createStatement().execute(query);

      query =
          "CREATE TABLE IF NOT EXISTS server_params (" +
              "name     TEXT    NOT NULL, " +
              "value    TEXT    NOT NULL, " +
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
      String selectUser = "UPDATE entries SET dh_params_sig WHERE serial_number = ?;";

      PreparedStatement ps = connection.prepareStatement(selectUser);
      ps.setString(1, serialNumber);

      int updated = ps.executeUpdate();

      if (updated == 0)
        throw new EntryNotFoundException();

    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  /*
    Server Parameters
  */
  public void insertParameter(ServerParameter parameter, String value) throws DatabaseException, CriticalDatabaseException {
    try {
      String paramName = parameter.val();

      // Check Parameter exists
      String statement = "SELECT * FROM server_params WHERE name = ?;";
      PreparedStatement ps = connection.prepareStatement(statement);
      ps.setString(1, paramName);

      ResultSet rs = ps.executeQuery();

      // Check exists
      if (rs.next()) {
        // Exists so we update it
        statement = "UPDATE server_params SET value = ? WHERE name = ?;";
        ps = connection.prepareStatement(statement);
        ps.setString(1, value);
        ps.setString(2, paramName);

      } else {
        // Does not exist so we create it
        statement = "INSERT INTO server_params (name, value) VALUES (?, ?);";
        ps = connection.prepareStatement(statement);
        ps.setString(1, paramName);
        ps.setString(2, value);
      }

      int updated = ps.executeUpdate();

      if (updated == 0)
        throw new FailedToInsertOrUpdateException();
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public String getParameter(ServerParameter parameter) throws DatabaseException, CriticalDatabaseException {
    try {
      String selectUser = "SELECT value FROM server_params WHERE name = ?;";

      PreparedStatement ps = connection.prepareStatement(selectUser);
      ps.setString(1, parameter.val());

      ResultSet rs = ps.executeQuery();

      // Param was not found
      if (!rs.next())
        throw new EntryNotFoundException();

      return rs.getString("value");
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public HashMap<String, String> getAllParameters() throws CriticalDatabaseException {
    try {
      String selectUser = "SELECT * FROM server_params;";

      PreparedStatement ps = connection.prepareStatement(selectUser);

      ResultSet rs = ps.executeQuery();

      HashMap<String, String> params = new HashMap<>();

      while (rs.next()) {
        params.put(rs.getString("name"), rs.getString("value"));
      }

      return params;
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }
}
