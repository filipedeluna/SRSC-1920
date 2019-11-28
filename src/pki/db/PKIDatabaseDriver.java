package pki.db;

import org.sqlite.JDBC;
import shared.errors.db.CriticalDatabaseException;
import shared.errors.db.DatabaseException;
import shared.errors.db.FailedToInsertException;

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
              "pkey            TEXT    NOT NULL, " +
              "revoked         INTEGER NOT NULL, " +
              "PRIMARY KEY (uuid)" +
              ");";

      connection.createStatement().execute(query);

    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public void insert(String uuid, String pKey) throws DatabaseException, CriticalDatabaseException {
    try {
      String insertQuery = "INSERT INTO entries (uuid, pKey, revoked) VALUES (?, ?, ?);";

      PreparedStatement ps = connection.prepareStatement(insertQuery);
      ps.setString(1, uuid);
      ps.setString(2, pKey);
      ps.setInt(3, 0);

      ps.executeUpdate();
    } catch (SQLException e) {
      if (e.getErrorCode() == ERR_UNIQUE_CONSTRAINT)
        throw new FailedToInsertException();

      throw new CriticalDatabaseException(e);
    }
  }

  public boolean isRevoked(String uuid, int port) throws DatabaseException, CriticalDatabaseException {
    try {
      String selectUser = "SELECT revoked FROM entries WHERE address = ? AND port = ?;";

      PreparedStatement ps = connection.prepareStatement(selectUser);
      ps.setString(1, address);
      ps.setInt(2, port);

      ResultSet rs = ps.executeQuery();

      if (!rs.next())
        throw new EntryNotFoundException();

      return rs.getInt("is_restricted") == 1;
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public ParameterSpec getChatroom(String address, int port) throws DatabaseException, CriticalDatabaseException {
    try {
      String selectUser = "SELECT * FROM chatrooms WHERE address = ? AND port = ?;";

      PreparedStatement ps = connection.prepareStatement(selectUser);
      ps.setString(1, address);
      ps.setInt(2, port);

      ResultSet rs = ps.executeQuery();

      // chatroom was not found
      if (!rs.next())
        throw new EntryNotFoundException();

      return new ParameterSpec(
          rs.getString("address"),
          rs.getInt("port"),
          rs.getString("sid"),
          rs.getString("sea"),
          rs.getInt("seaks"),
          rs.getString("mode"),
          rs.getString("padding"),
          rs.getString("inthash"),
          rs.getString("mac"),
          rs.getInt("macks")
      );

    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public boolean chatroomExists(String address, int port) throws CriticalDatabaseException {
    try {
      String query = "SELECT * FROM chatrooms WHERE address = ? AND port = ?;";

      PreparedStatement ps = connection.prepareStatement(query);

      ps.setString(1, address);
      ps.setInt(2, port);

      ResultSet rs = ps.executeQuery();

      return rs.next();
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public void insertUserIntoRoom(String address, int port, String name) throws FailedToInsertException {
    try {
      String query = "INSERT INTO auth (address, port, username) VALUES (?, ?, ?);";

      PreparedStatement ps = connection.prepareStatement(query);

      ps.setString(1, address);
      ps.setInt(2, port);
      ps.setString(3, name);

      ps.executeUpdate();

    } catch (SQLException e) {
      if (e.getErrorCode() == ERR_UNIQUE_CONSTRAINT)
        throw new FailedToInsertException();
    }
  }

  public void insertUsersInChatroom(String address, int port, LinkedHashSet<String> userList) throws CriticalDatabaseException {
    try {
      String insertQuery;
      PreparedStatement ps;

      connection.setAutoCommit(false);

      LinkedHashSet<PreparedStatement> statements = new LinkedHashSet<>();

      for (String user : userList) {
        insertQuery = "INSERT INTO auth (address, port, username) VALUES (?, ?, ?);";

        ps = connection.prepareStatement(insertQuery);
        ps.setString(1, address);
        ps.setInt(2, port);
        ps.setString(3, user);

        statements.add(ps);
      }

      for (PreparedStatement statement : statements) {
        try {
          statement.executeUpdate();
        } catch (SQLException e) {
          if (e.getErrorCode() == ERR_UNIQUE_CONSTRAINT)
            continue; // User already exists, continue as normal

          connection.rollback();

          throw e;
        }
      }

      connection.setAutoCommit(true);
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public boolean isInChatroomAuthList(String address, int port, String user) throws CriticalDatabaseException {
    try {
      String selectUser = "SELECT * FROM auth WHERE address = ? AND port = ? AND username = ?;";

      PreparedStatement ps = connection.prepareStatement(selectUser);

      ps.setString(1, address);
      ps.setInt(2, port);
      ps.setString(3, user);

      ResultSet rs = ps.executeQuery();

      // User is or isnt in auth list
      return rs.next();
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public void insertUser(UserSpec uSpec) throws DatabaseException, CriticalDatabaseException {
    try {
      String insertQuery =
          "INSERT INTO users (username, pwd_hash, pwd_seed, is_admin) " +
              "VALUES (?, ?, ?, ?);";

      PreparedStatement ps = connection.prepareStatement(insertQuery);

      ps.setString(1, uSpec.USERNAME);
      ps.setString(2, uSpec.PASSWORD_HASH);
      ps.setString(3, uSpec.PASSWORD_SEED);
      ps.setInt(4, uSpec.IS_ADMIN ? 1 : 0);

      ps.executeUpdate();
    } catch (SQLException e) {
      if (e.getErrorCode() == ERR_UNIQUE_CONSTRAINT)
        throw new FailedToInsertException();

      throw new CriticalDatabaseException(e);
    }
  }

  public void deleteUser(String username) throws DatabaseException, CriticalDatabaseException {
    try {
      String deleteQuery = "DELETE FROM users WHERE username = ?;";

      PreparedStatement ps = connection.prepareStatement(deleteQuery);
      ps.setString(1, username);

      if (ps.executeUpdate() != 1)
        throw new FailedToDeleteException();

    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public UserSpec getUser(String username) throws DatabaseException, CriticalDatabaseException {
    try {
      String selectUser = "SELECT * FROM users WHERE username = ?;";

      PreparedStatement ps = connection.prepareStatement(selectUser);
      ps.setString(1, username);

      ResultSet rs = ps.executeQuery();

      // User was not found
      if (!rs.next())
        throw new EntryNotFoundException();

      return new UserSpec(
          rs.getString("username"),
          rs.getString("pwd_hash"),
          rs.getString("pwd_seed"),
          rs.getInt("is_admin") == 1
      );
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public boolean userExists(String username) throws CriticalDatabaseException {
    try {
      String selectUser = "SELECT * FROM users WHERE username = ?;";

      PreparedStatement ps = connection.prepareStatement(selectUser);
      ps.setString(1, username);

      ResultSet rs = ps.executeQuery();

      return rs.next();
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public void deleteUsersFromChatroom(String address, int port, LinkedHashSet<String> userList) throws CriticalDatabaseException {
    try {
      String insertQuery;
      PreparedStatement ps;

      connection.setAutoCommit(false);

      LinkedHashSet<PreparedStatement> statements = new LinkedHashSet<>();

      for (String user : userList) {
        insertQuery = "DELETE FROM auth WHERE address = ? AND port = ? AND username = ? ;";

        ps = connection.prepareStatement(insertQuery);
        ps.setString(1, address);
        ps.setInt(2, port);
        ps.setString(3, user);

        statements.add(ps);
      }

      for (PreparedStatement statement : statements) {
        try {
          statement.executeUpdate();
        } catch (SQLException e) {
          if (e.getErrorCode() == ERR_NOT_FOUND)
            continue; // already deleted or does not exist, continue as normal

          connection.rollback();

          throw e;
        }
      }

      connection.setAutoCommit(true);
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }
}
