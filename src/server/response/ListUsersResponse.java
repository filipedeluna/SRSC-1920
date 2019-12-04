package server.response;

public final class ListUsersResponse extends OkResponseWithNonce {
  private String users;

  public ListUsersResponse(String nonce, String users) {
    super(nonce);
    this.users = users;
  }
}
