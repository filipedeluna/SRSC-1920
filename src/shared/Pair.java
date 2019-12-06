package shared;

public final class Pair<K, V> {
  private final K A;
  private final V B;

  public Pair(K a, V b) {
    this.A = a;
    this.B = b;
  }

  public K getA() {
    return A;
  }

  public V getB() {
    return B;
  }
}
