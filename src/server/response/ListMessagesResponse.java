package server.response;

import java.util.ArrayList;

public final class ListMessagesResponse extends OkResponseWithNonce {
  private ArrayList<String> receivedMessageIds;
  private ArrayList<Integer> sentMessageIds;

  public ListMessagesResponse(String nonce, ArrayList<String> receivedMessageIds, ArrayList<Integer> sentMessageIds) {
    super(nonce);
    this.receivedMessageIds = receivedMessageIds;
    this.sentMessageIds = sentMessageIds;
  }

  public ArrayList<String> getReceivedMessageIds() {
    return receivedMessageIds;
  }

  public ArrayList<Integer> getSentMessageIds() {
    return sentMessageIds;
  }
}
