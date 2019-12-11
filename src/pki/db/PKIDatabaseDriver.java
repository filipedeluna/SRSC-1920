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
              "cert_sn         TEXT PRIMARY KEY, " +
              "cert_hash       TEXT NOT NULL, " +
              "revoked         INTEGER NOT NULL DEFAULT 0 " +
              ");";

      connection.createStatement().execute(query);
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public void register(String certSN, String certHash) throws DatabaseException, CriticalDatabaseException {
    try {
      String insertQuery = "INSERT INTO entries (cert_sn, cert_hash) VALUES (?, ?);";

      PreparedStatement ps = connection.prepareStatement(insertQuery);
      ps.setString(1, certSN);
      ps.setString(2, certHash);

      ps.executeUpdate();
    } catch (SQLException e) {
      if (e.getErrorCode() == ERR_UNIQUE_CONSTRAINT)
        throw new DuplicateEntryException();

      throw new CriticalDatabaseException(e);
    }
  }

  public boolean isValid(String certSN, String certHash) throws CriticalDatabaseException {
    try {
      String selectUser = "SELECT * FROM entries WHERE cert_sn = ? AND cert_hash = ? AND revoked = 0;";

      PreparedStatement ps = connection.prepareStatement(selectUser);
      ps.setString(1, certSN);
      ps.setString(2, certHash);

      ResultSet rs = ps.executeQuery();

      return rs.next();
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public void revoke(String cert_sn) throws DatabaseException, CriticalDatabaseException {
    try {
      String selectUser = "UPDATE entries SET revoked = 1 WHERE cert_sn = ?;";

      PreparedStatement ps = connection.prepareStatement(selectUser);
      ps.setString(1, cert_sn);

      int updated = ps.executeUpdate();

      if (updated == 0)
        throw new EntryNotFoundException();

    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }
}
