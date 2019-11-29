package pki.db;

import org.sqlite.JDBC;
import shared.errors.db.*;

import java.security.PublicKey;
import java.sql.*;
import java.util.Base64;
import java.util.LinkedHashSet;

public final class PKIDatabaseDriver {
  private static final int ERR_UNIQUE_CONSTRAINT = 19;
  private static final int ERR_NOT_FOUND = 12;

  private Connection connection;

  public PKIDatabaseDriver(String path) throws CriticalDatabaseException {
    // Connect to file
    connection = connect(path);

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
              "username        TEXT    NOT NULL, " +
              "cert            TEXT    NOT NULL UNIQUE, " +
              "revoked         INTEGER NOT NULL, " +
              "PRIMARY KEY (username)" +
              ");";

      connection.createStatement().execute(query);

    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public void register(String username, String cert) throws DatabaseException, CriticalDatabaseException {
    try {
      String insertQuery = "INSERT INTO entries (username, cert, revoked) VALUES (?, ?);";

      PreparedStatement ps = connection.prepareStatement(insertQuery);
      ps.setString(1, username);
      ps.setString(2, cert);
      ps.setInt(3, 0);

      ps.executeUpdate();
    } catch (SQLException e) {
      if (e.getErrorCode() == ERR_UNIQUE_CONSTRAINT)
        throw new FailedToInsertException();

      throw new CriticalDatabaseException(e);
    }
  }

  public boolean isRegistered(String username, String cert) throws CriticalDatabaseException {
    try {
      String selectUser = "SELECT * FROM entries WHERE username = ? OR cert = ?;";

      PreparedStatement ps = connection.prepareStatement(selectUser);
      ps.setString(1, username);
      ps.setString(2, cert);

      ResultSet rs = ps.executeQuery();
      return rs.next();
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public boolean isRevoked(String cert) throws DatabaseException, CriticalDatabaseException {
    try {
      String selectUser = "SELECT revoked FROM entries WHERE cert = ?;";

      PreparedStatement ps = connection.prepareStatement(selectUser);
      ps.setString(1, cert);

      ResultSet rs = ps.executeQuery();

      if (!rs.next())
        throw new EntryNotFoundException();

      return rs.getInt("is_restricted") == 1;
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public void revoke(String username, String cert) throws DatabaseException, CriticalDatabaseException {
    try {
      String selectUser = "UPDATE entries SET revoked = 1 WHERE username = ? OR cert = ?;";

      PreparedStatement ps = connection.prepareStatement(selectUser);
      ps.setString(1, username);
      ps.setString(2, cert);

      int updated = ps.executeUpdate();

      if (updated == 0)
        throw new FailedToUpdateException();

    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }
}
