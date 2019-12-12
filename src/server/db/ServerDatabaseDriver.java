package server.db;

import org.sqlite.JDBC;
import shared.utils.crypto.B64Helper;
import shared.wrappers.Message;
import shared.wrappers.Receipt;
import shared.wrappers.User;
import shared.Pair;
import shared.errors.db.*;
import shared.parameters.ServerParameterMap;
import shared.parameters.ServerParameter;

import java.sql.*;
import java.util.ArrayList;

public final class ServerDatabaseDriver {
  private static final int ERR_UNIQUE_CONSTRAINT = 19;
  private static final int ERR_FOREIGN_KEY_CONSTRAINT = 787;

  private Connection connection;
  private B64Helper b64Helper;

  public ServerDatabaseDriver(String dbPath) throws CriticalDatabaseException {
    // Connect to file
    connection = connect(dbPath);

    // Create tables they do not exist
    createTables();

    b64Helper = new B64Helper();
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
              "user_id            INTEGER PRIMARY KEY, " +
              "uuid               TEXT    NOT NULL UNIQUE, " +
              "pub_key            TEXT    NOT NULL, " +
              // Security data
              "dh_sea_pub_key     TEXT    NOT NULL, " +
              "dh_mac_pub_key     TEXT    NOT NULL, " +
              "sea_spec           TEXT    NOT NULL, " + // User chosen sea spec
              "mac_spec           TEXT    NOT NULL, " + // User chosen mac spec
              "sec_data_signature TEXT    NOT NULL " + // Signature of all security data
              ");";

      connection.createStatement().execute(query);

      query =
          "CREATE TABLE IF NOT EXISTS messages (" +
              "message_id       INTEGER PRIMARY KEY AUTOINCREMENT, " +
              "sender_id        INTEGER NOT NULL, " +
              "receiver_id      INTEGER NOT NULL, " +
              "read             INTEGER NOT NULL DEFAULT 0, " + // Boolean - 0 of not read, 1 if read
              "text             TEXT, " +
              "attachment_data  TEXT, " +
              "attachments      BLOB, " +
              "cipher_iv        TEXT, " + // Sea IV for cipher used in encryption or null if none used
              "sender_signature TEXT, " + // Signed with sender public key
              "FOREIGN KEY (sender_id)   REFERENCES users(user_id)," +
              "FOREIGN KEY (receiver_id) REFERENCES users(user_id)" +
              ");";

      connection.createStatement().execute(query);

      query =
          "CREATE TABLE IF NOT EXISTS receipts (" +
              "message_id         INTEGER NOT NULL, " +
              "date               TEXT    NOT NULL, " +
              "receiver_signature TEXT NOT NULL, " + // Reader signature of message contents with private key
              "FOREIGN KEY (message_id) REFERENCES messages(message_id)" +
              ");";

      connection.createStatement().execute(query);

      query =
          "CREATE TABLE IF NOT EXISTS server_params (" +
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
  public int insertUser(User user) throws CriticalDatabaseException, DuplicateEntryException {
    try {
      // Insert user
      String insertQuery = "INSERT INTO users (uuid, pub_key, dh_sea_pub_key, dh_mac_pub_key, sea_spec, mac_spec, sec_data_signature) VALUES (?, ?, ?, ?, ?, ?, ?);";

      PreparedStatement ps = connection.prepareStatement(insertQuery);
      ps.setString(1, user.getUuid());
      ps.setString(2, user.getPubKey());
      // Security data
      ps.setString(3, user.getDhSeaPubKey());
      ps.setString(4, user.getDhMacPubKey());
      ps.setString(5, user.getSeaSpec());
      ps.setString(6, user.getMacSpec());
      ps.setString(7, user.getSecDataSignature());

      ps.executeUpdate();

      ResultSet rs = ps.getGeneratedKeys();

      return rs.getInt(1);
    } catch (SQLException e) {
      if (e.getErrorCode() == ERR_UNIQUE_CONSTRAINT)
        throw new DuplicateEntryException();

      throw new CriticalDatabaseException(e);
    }
  }

  public User getUserById(int id) throws CriticalDatabaseException, EntryNotFoundException {
    try {
      String selectUser = "SELECT * FROM users WHERE user_id = ?;";

      PreparedStatement ps = connection.prepareStatement(selectUser);
      ps.setString(1, String.valueOf(id));

      ResultSet rs = ps.executeQuery();

      if (!rs.next())
        throw new EntryNotFoundException();

      return new User(
          rs.getInt("user_id"),
          rs.getString("pub_key"),
          rs.getString("dh_sea_pub_key"),
          rs.getString("dh_mac_pub_key"),
          rs.getString("sea_spec"),
          rs.getString("mac_spec"),
          rs.getString("sec_data_signature")
      );
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public User getUserByUUID(String uuid) throws CriticalDatabaseException, EntryNotFoundException {
    try {
      String selectUser = "SELECT * FROM users WHERE uuid = ?;";

      PreparedStatement ps = connection.prepareStatement(selectUser);
      ps.setString(1, uuid);

      ResultSet rs = ps.executeQuery();

      if (!rs.next())
        throw new EntryNotFoundException();

      return new User(
          rs.getInt("user_id"),
          rs.getString("pub_key"),
          rs.getString("dh_sea_pub_key"),
          rs.getString("dh_mac_pub_key"),
          rs.getString("sea_spec"),
          rs.getString("mac_spec"),
          rs.getString("sec_data_signature")
      );
    } catch (SQLException e) {
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
            rs.getInt("user_id"),
            rs.getString("pub_key"),
            rs.getString("dh_sea_pub_key"),
            rs.getString("dh_mac_pub_key"),
            rs.getString("sea_spec"),
            rs.getString("mac_spec"),
            rs.getString("sec_data_signature")
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

  public int insertMessage(Message msg) throws CriticalDatabaseException, FailedToInsertException {
    try {
      String insertQuery = "INSERT INTO messages (sender_id, receiver_id, text, attachment_data, attachments, cipher_iv, sender_signature) " +
          "VALUES (?, ?, ?, ?, ?, ?, ?);";

      PreparedStatement ps = connection.prepareStatement(insertQuery);
      ps.setInt(1, msg.getSenderId());
      ps.setInt(2, msg.getReceiverId());
      ps.setString(3, msg.getText());
      ps.setString(4, msg.getAttachmentData());
      ps.setBytes(5, b64Helper.decode(msg.getAttachments()));
      ps.setString(6, msg.getIV());
      ps.setString(7, msg.getSenderSignature());

      ps.executeUpdate();

      ResultSet rs = ps.getGeneratedKeys();

      return rs.getInt(1);
    } catch (SQLException e) {
      if (e.getErrorCode() == ERR_FOREIGN_KEY_CONSTRAINT)
        throw new FailedToInsertException();

      throw new CriticalDatabaseException(e);
    }
  }

  public Message getMessage(int messageId) throws CriticalDatabaseException, EntryNotFoundException {
    try {
      String insertQuery = "SELECT * FROM messages WHERE message_id = ?;";

      PreparedStatement ps = connection.prepareStatement(insertQuery);
      ps.setInt(1, messageId);

      ResultSet rs = ps.executeQuery();

      if (!rs.next())
        throw new EntryNotFoundException();

      return new Message(
          rs.getInt("sender_id"),
          rs.getString("text"),
          rs.getString("attachment_data"),
          b64Helper.encode(rs.getBytes("attachments")),
          rs.getString("cipher_iv"),
          rs.getString("sender_signature")
      );
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  public void setMessageAsRead(int message_id) throws CriticalDatabaseException, EntryNotFoundException {
    try {
      String selectUser = "UPDATE messages SET read = 1 WHERE message_id = ?;";

      PreparedStatement ps = connection.prepareStatement(selectUser);
      ps.setInt(1, message_id);

      int updated = ps.executeUpdate();

      if (updated == 0)
        throw new EntryNotFoundException();

    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  /*
    RECEIPT BOX
  */

  public void insertReceipt(Receipt rcpt) throws CriticalDatabaseException, FailedToInsertException {
    try {
      // Insert receipt
      String insertQuery = "INSERT INTO receipts (message_id, date, receiver_signature) VALUES (?, ?, ?);";

      PreparedStatement ps = connection.prepareStatement(insertQuery);
      ps.setInt(1, rcpt.getMessageId());
      ps.setString(2, rcpt.getDate());
      ps.setString(3, rcpt.getReceiverSignature());

      ps.executeUpdate();

      // Set message as read
      String updateQuery = "UPDATE messages (read) VALUES (1) WHERE message_id = ?;";

      connection.prepareStatement(updateQuery);
      ps.setInt(1, rcpt.getMessageId());

      ps.executeUpdate();
    } catch (SQLException e) {
      if (e.getErrorCode() == ERR_FOREIGN_KEY_CONSTRAINT)
        throw new FailedToInsertException();

      throw new CriticalDatabaseException(e);
    }
  }

  public ArrayList<Receipt> getReceipts(int messageId) throws CriticalDatabaseException {
    try {
      String insertQuery =
          "SELECT r.message_id AS message_id, m.sender_id AS sender_id, r.date AS mdate, r.receiver_signature AS receiver_signature " +
              "FROM receipts r JOIN messages m ON r.message_id = m.message_id WHERE m.message_id = ?;";

      PreparedStatement ps = connection.prepareStatement(insertQuery);
      ps.setInt(1, messageId);

      ResultSet rs = ps.executeQuery();

      ArrayList<Receipt> receipts = new ArrayList<>();

      while (rs.next()) {
        receipts.add(new Receipt(
                rs.getInt("message_id"),
                rs.getInt("sender_id"),
                rs.getString("mdate"),
                rs.getString("receiver_signature")
            )
        );
      }

      return receipts;
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }

  /*
    Server Parameters
  */
  public void insertParameter(ServerParameter parameter, String value) throws CriticalDatabaseException, FailedToInsertException {
    try {
      // Does not exist so we create it
      String statement = "INSERT INTO server_params (name, value) VALUES (?, ?);";
      PreparedStatement ps = connection.prepareStatement(statement);
      ps.setString(1, parameter.dbName());
      ps.setString(2, value);

      int updated = ps.executeUpdate();

      if (updated == 0)
        throw new FailedToInsertException();

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

  public ServerParameterMap getAllParameters() throws CriticalDatabaseException {
    try {
      String selectUser = "SELECT * FROM server_params ORDER BY ROWID;";

      PreparedStatement ps = connection.prepareStatement(selectUser);

      ResultSet rs = ps.executeQuery();

      ServerParameterMap params = new ServerParameterMap();

      while (rs.next()) {
        params.put(
            rs.getString("name"),
            rs.getString("value"));
      }

      return params;
    } catch (SQLException e) {
      throw new CriticalDatabaseException(e);
    }
  }
}
