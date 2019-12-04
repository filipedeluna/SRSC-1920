package server.db;

import org.sqlite.JDBC;
import server.db.wrapper.Message;
import server.db.wrapper.Receipt;
import server.db.wrapper.User;
import server.errors.parameters.ParameterException;
import shared.Pair;
import shared.errors.db.*;

import java.sql.*;
import java.util.ArrayList;
import java.util.HashMap;

public final class ServerDatabaseDriver {
  private static final int ERR_UNIQUE_CONSTRAINT = 19;
  private static final int ERR_NOT_FOUND = 12;
  private static final int ERR_FOREIGN_KEY_CONSTRAINT = 787;

  private Connection connection;
  private int paramCounter;

  public ServerDatabaseDriver(String dbPath) throws CriticalDatabaseException {
    // Connect to file
    connection = connect(dbPath);
    paramCounter = 0; // control insertion of params so the order for hashing is known

    // Create tables they do not exist
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
          "CREATE TABLE IF NOT EXISTS users (" +
              "user_id    INTEGER PRIMARY KEY, " +
              "uuid       TEXT    NOT NULL UNIQUE, " +
              "pub_key    TEXT    NOT NULL, " +
              // Security data
              "dh_pub_key TEXT    NOT NULL, " +
              // Signature of all data
              "signature  TEXT    NOT NULL, " +
              ");";

      connection.createStatement().execute(query);

      query =
          "CREATE TABLE IF NOT EXISTS messages (" +
              "message_id       INTEGER PRIMARY KEY AUTOINCREMENT, " +
              "sender_id        INTEGER NOT NULL, " +
              "receiver_id      INTEGER NOT NULL, " +
              "read             INTEGER NOT NULL DEFAULT 0, " +
              "text             TEXT, " +
              "attachment_data  TEXT, " +
              "attachments      BLOB, " +
              // Mac hash with secret client key to prevent tampering
              "mac_hash         TEXT, " +
              "FOREIGN KEY (sender_id)   REFERENCES users(user_id)," +
              "FOREIGN KEY (receiver_id) REFERENCES users(user_id)" +
              ");";

      connection.createStatement().execute(query);

      query =
          "CREATE TABLE IF NOT EXISTS receipts (" +
              "message_id INTEGER NOT NULL, " +
              "date       TEXT    NOT NULL, " +
              // Reader signature of message contents with private key
              "signature  TEXT    NOT NULL, " +
              "FOREIGN KEY (message_id) REFERENCES messages(message_id)," +
              ");";

      connection.createStatement().execute(query);

      query =
          "CREATE TABLE IF NOT EXISTS server_params (" +
              "id    INTEGER NOT NULL UNIQUE, " +
              "name  TEXT    NOT NULL UNIQUE, " +
              "value TEXT    NOT NULL " +
              ");";

      connection.createStatement().execute(query);
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  /*
    USERS
  */
  public int insertUser(User user) throws DatabaseException, CriticalDatabaseException {
    try {
      // Insert user
      String insertQuery = "INSERT INTO users (uuid, pub_key, dh_value, signature) VALUES (?, ?, ?, ?);";

      PreparedStatement ps = connection.prepareStatement(insertQuery);
      ps.setString(1, user.uuid);
      ps.setString(2, user.pubKey);
      // Security data
      ps.setString(3, user.dhValue);
      ps.setString(4, user.secDataSignature);

      ps.executeUpdate();

      ResultSet rs = ps.getGeneratedKeys();

      return rs.getInt("user_id");
    } catch (SQLException e) {
      if (e.getErrorCode() == ERR_UNIQUE_CONSTRAINT)
        throw new DuplicateEntryException();

      throw new CriticalDatabaseException(e);
    }
  }

  public User getUser(int id) throws CriticalDatabaseException, DatabaseException {
    try {
      String selectUser = "SELECT * FROM users WHERE user_id = ?;";

      PreparedStatement ps = connection.prepareStatement(selectUser);
      ps.setString(1, String.valueOf(id));

      ResultSet rs = ps.executeQuery();

      rs.next();

      return new User(
          rs.getString("user_id"),
          null,
          rs.getString("pub_key"),
          rs.getString("dh_value"),
          rs.getString("signature")
      );
    } catch (SQLException e) {
      if (e.getErrorCode() == ERR_NOT_FOUND)
        throw new EntryNotFoundException();

      throw new CriticalDatabaseException(e);
    }
  }

  public ArrayList<User> getAllUsers() throws CriticalDatabaseException {
    try {
      String selectUser = "SELECT * FROM users;";

      PreparedStatement ps = connection.prepareStatement(selectUser);

      ResultSet rs = ps.executeQuery();

      ArrayList<User> users = new ArrayList<>();

      while (rs.next()) {
        users.add(new User(
            rs.getString("user_id"),
            null,
            rs.getString("pub_key"),
            rs.getString("dh_value"),
            rs.getString("signature")
        ));
      }

      return users;
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  /*
    MESSAGE BOX
  */
  public ArrayList<Integer> getUnreadMessages(int userId) throws CriticalDatabaseException {
    try {
      String insertQuery = "SELECT * FROM messages WHERE receiver_id = ? AND read = 0;";

      PreparedStatement ps = connection.prepareStatement(insertQuery);
      ps.setInt(1, userId);

      ResultSet rs = ps.executeQuery();

      ArrayList<Integer> messageIds = new ArrayList<>();

      while (rs.next())
        messageIds.add(rs.getInt("message_id"));

      return messageIds;
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public Pair<ArrayList<String>, ArrayList<Integer>> getAllMessages(int userId) throws CriticalDatabaseException {
    try {
      // Get Received messages
      String insertQuery = "SELECT * FROM messages WHERE receiver_id = ?;";

      PreparedStatement ps = connection.prepareStatement(insertQuery);
      ps.setInt(1, userId);

      ResultSet rs = ps.executeQuery();

      ArrayList<String> receivedMessageIds = new ArrayList<>();

      // Verify if message has been read
      int read;
      int messageId;

      while (rs.next()) {
        read = rs.getInt("read");
        messageId = rs.getInt("receiver_id");

        receivedMessageIds.add((read == 1 ? "_" : "") + messageId);
      }

      // Get Sent messages
      insertQuery = "SELECT * FROM messages WHERE sender_id = ?;";

      ps = connection.prepareStatement(insertQuery);
      ps.setInt(1, userId);

      rs = ps.executeQuery();

      ArrayList<Integer> sentMessageIds = new ArrayList<>();

      while (rs.next())
        sentMessageIds.add(rs.getInt("sender_id"));

      return new Pair<>(receivedMessageIds, sentMessageIds);
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public int insertMessage(Message msg) throws CriticalDatabaseException, DatabaseException {
    try {
      String insertQuery = "INSERT INTO messages (sender_id, receiver_id, text, attachment_data, attachments, mac_hash) " +
          "VALUES (?, ?, ?, ?, ?, ?);";

      PreparedStatement ps = connection.prepareStatement(insertQuery);
      ps.setInt(1, msg.senderId);
      ps.setInt(2, msg.receiverId);
      ps.setString(3, msg.text);
      ps.setString(4, msg.attachmentData);
      ps.setBytes(5, msg.attachments);
      ps.setString(6, msg.macHash);

      ps.executeUpdate();

      ResultSet rs = ps.getGeneratedKeys();

      return rs.getInt("message_id");
    } catch (SQLException e) {
      if (e.getErrorCode() == ERR_FOREIGN_KEY_CONSTRAINT)
        throw new GenericItemNotFoundException("user");

      throw new CriticalDatabaseException(e);
    }
  }

  public Message getMessage(int messageId) throws CriticalDatabaseException, DatabaseException {
    try {
      String insertQuery = "SELECT * FROM messages WHERE message_id = ?;";

      PreparedStatement ps = connection.prepareStatement(insertQuery);
      ps.setInt(1, messageId);

      ResultSet rs = ps.executeQuery();

      rs.next();

      return new Message(
          rs.getInt("sender_id"),
          rs.getString("text"),
          rs.getString("attachment_data"),
          rs.getBytes("attachments")
      );
    } catch (SQLException e) {
      if (e.getErrorCode() == ERR_NOT_FOUND)
        throw new EntryNotFoundException();

      throw new CriticalDatabaseException(e);
    }
  }

  /*
    RECEIPT BOX
  */

  public void insertReceipt(Receipt rcpt) throws CriticalDatabaseException, GenericItemNotFoundException {
    try {
      // Insert receipt
      String insertQuery = "INSERT INTO receipts (message_id, date, receiver_signature) VALUES (?, ?, ?);";

      PreparedStatement ps = connection.prepareStatement(insertQuery);
      ps.setInt(1, rcpt.messageId);
      ps.setString(2, rcpt.date);
      ps.setString(3, rcpt.signature);

      ps.executeUpdate();

      // Set message as read
      String updateQuery = "UPDATE messages (read) VALUES (1) WHERE message_id = ?;";

      connection.prepareStatement(updateQuery);
      ps.setInt(1, rcpt.messageId);

      ps.executeUpdate();
    } catch (SQLException e) {
      if (e.getErrorCode() == ERR_FOREIGN_KEY_CONSTRAINT)
        throw new GenericItemNotFoundException("message");

      throw new CriticalDatabaseException(e);
    }
  }

  public ArrayList<Receipt> getReceipts(int messageId) throws CriticalDatabaseException, DatabaseException {
    try {
      String insertQuery =
          "SELECT r.message_id AS message_id, m.sender_id AS sender_id, m.date AS date, m.signature AS signature " +
              "FROM receipts r JOIN messages m ON r.message_id = m.message_id WHERE message_id = ?;";

      PreparedStatement ps = connection.prepareStatement(insertQuery);
      ps.setInt(1, messageId);

      ResultSet rs = ps.executeQuery();

      ArrayList<Receipt> receipts = new ArrayList<>();

      while (rs.next()) {
        receipts.add(new Receipt(
                rs.getInt("message_id"),
                rs.getInt("sender_id"),
                rs.getString("date"),
                rs.getString("signature")
            )
        );
      }

      return receipts;
    } catch (SQLException e) {
      if (e.getErrorCode() == ERR_FOREIGN_KEY_CONSTRAINT)
        throw new GenericItemNotFoundException("message");

      throw new CriticalDatabaseException(e);
    }
  }

  /*
    Server Parameters
  */
  public void insertParameter(ServerParameterType parameter, String value) throws DatabaseException, CriticalDatabaseException {
    try {
      // Does not exist so we create it
      String statement = "INSERT INTO server_params (id, name, value) VALUES (?, ?, ?);";
      PreparedStatement ps = connection.prepareStatement(statement);
      ps.setInt(1, paramCounter++);
      ps.setString(2, parameter.dbName());
      ps.setString(3, value);

      int updated = ps.executeUpdate();

      if (updated == 0)
        throw new FailedToInsertOrUpdateException();

    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public void deleteAllParameters() throws CriticalDatabaseException {
    try {
      // Check Parameter exists
      String statement = "DELETE FROM server_params;";
      PreparedStatement ps = connection.prepareStatement(statement);

      ps.executeUpdate();
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  // TODO useless?
  public String getParameter(ServerParameterType parameter) throws DatabaseException, CriticalDatabaseException {
    try {
      String selectUser = "SELECT value FROM server_params WHERE name = ?;";

      PreparedStatement ps = connection.prepareStatement(selectUser);
      ps.setString(1, parameter.dbName());

      ResultSet rs = ps.executeQuery();

      // Param was not found
      if (!rs.next())
        throw new EntryNotFoundException();

      return rs.getString("value");
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public ServerParameterMap getAllParameters() throws CriticalDatabaseException {
    try {
      String selectUser = "SELECT * FROM server_params ORDER BY id;";

      PreparedStatement ps = connection.prepareStatement(selectUser);

      ResultSet rs = ps.executeQuery();

      ServerParameterMap params = new ServerParameterMap();

      while (rs.next()) {
        params.put(
            rs.getInt("id"),
            rs.getString("name"),
            rs.getString("value"));
      }

      return params;
    } catch (SQLException | ParameterException e) {
      if (e instanceof ParameterException)
        throw new CriticalDatabaseException((ParameterException) e);

      throw new CriticalDatabaseException((SQLException) e);
    }
  }

  /*
    UTILS
  */
}
