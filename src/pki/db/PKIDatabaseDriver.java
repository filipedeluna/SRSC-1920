package pki.db;

import org.sqlite.JDBC;
import shared.errors.db.*;

import java.sql.*;

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
              "pkey_hash       TEXT    NOT NULL UNIQUE, " +
              "cert_hash       TEXT    NOT NULL UNIQUE, " +
              "revoked         INTEGER NOT NULL, " +
              "PRIMARY KEY (pkey_hash, cert_hash)" +
              ");";

      connection.createStatement().execute(query);
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public void register(String pkeyHash, String certHash) throws DatabaseException, CriticalDatabaseException {
    try {
      String insertQuery = "INSERT INTO entries (pkey_hash, cert_hash, revoked) VALUES (?, ?, ?);";

      PreparedStatement ps = connection.prepareStatement(insertQuery);
      ps.setString(1, pkeyHash);
      ps.setString(2, certHash);
      ps.setInt(3, 0);

      ps.executeUpdate();
    } catch (SQLException e) {
      if (e.getErrorCode() == ERR_UNIQUE_CONSTRAINT)
        throw new DuplicateEntryException();

      throw new CriticalDatabaseException(e);
    }
  }

  public boolean isValid(String certHash) throws CriticalDatabaseException {
    try {
      String selectUser = "SELECT * FROM entries WHERE cert_hash = ? AND revoked = 0;";

      PreparedStatement ps = connection.prepareStatement(selectUser);
      ps.setString(1, certHash);

      ResultSet rs = ps.executeQuery();
      return rs.next();
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public void revoke(String pkeyHash, String certHash) throws DatabaseException, CriticalDatabaseException {
    try {
      String selectUser = "UPDATE entries SET revoked = 1 WHERE pkey_hash = ? AND cert_hash = ?;";

      PreparedStatement ps = connection.prepareStatement(selectUser);
      ps.setString(1, pkeyHash);
      ps.setString(2, certHash);

      int updated = ps.executeUpdate();

      if (updated == 0)
        throw new EntryNotFoundException();

    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }
}
