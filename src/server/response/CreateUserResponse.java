package server.response;

public final class CreateUserResponse extends OkResponseWithNonce {
  private int userId;

  public CreateUserResponse(String nonce, int userId) {
    super(nonce);
    this.userId = userId;
  }
}
