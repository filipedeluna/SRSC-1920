package shared.response.server;

import shared.response.OkResponseWithNonce;

import java.util.ArrayList;

public final class ListNewMessagesResponse extends OkResponseWithNonce {
  private final ArrayList<Integer> newMessageIds;

  public ListNewMessagesResponse(String nonce, ArrayList<Integer> newMessageIds) {
    super(nonce);
    this.newMessageIds = newMessageIds;
  }

  public ArrayList<Integer> getNewMessageIds() {
    return newMessageIds;
  }

}
