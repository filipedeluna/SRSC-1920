package server.response;

import java.util.ArrayList;

public final class ListNewMessagesResponse extends OkResponseWithNonce {
  private ArrayList<Integer> newMessageIds;

  public ListNewMessagesResponse(String nonce, ArrayList<Integer> newMessageIds) {
    super(nonce);
    this.newMessageIds = newMessageIds;
  }
}
