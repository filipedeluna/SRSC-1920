package shared.response.server;

import shared.wrappers.User;
import shared.response.OkResponseWithNonce;

public class LoginResponse extends OkResponseWithNonce {
  private final User user;

  public LoginResponse(String nonce, User user) {
    super(nonce);
    this.user = user;
  }

  public User getUser() {
    return user;
  }
}