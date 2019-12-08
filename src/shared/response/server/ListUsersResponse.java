package shared.response.server;

import shared.response.OkResponseWithNonce;
import shared.wrappers.User;

import java.util.ArrayList;

public final class ListUsersResponse extends OkResponseWithNonce {
  private final ArrayList<User> users;

  public ListUsersResponse(String nonce, ArrayList<User> users) {
    super(nonce);
    this.users = users;
  }

  public ArrayList<User> getUsers() {
    return users;
  }
}
