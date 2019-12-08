package shared.response.server;

import shared.response.OkResponseWithNonce;

public final class CreateUserResponse extends OkResponseWithNonce {
  private final int userId;

  public CreateUserResponse(String nonce, int userId) {
    super(nonce);
    this.userId = userId;
  }

  public int getUserId() {
    return userId;
  }
}
