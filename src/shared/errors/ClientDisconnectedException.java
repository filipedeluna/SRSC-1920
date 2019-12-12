package shared.errors;

public final class ClientDisconnectedException extends Exception {
    public ClientDisconnectedException() {
      super("Client has disconnected.");
    }
}
