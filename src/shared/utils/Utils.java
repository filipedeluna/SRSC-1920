package shared.utils;

public final class Utils {
  public static byte[] joinByteArrays(byte[]... arrays) {
    byte[] finalArray = new byte[0];

    byte[] tempArray;
    for (byte[] array : arrays) {
      tempArray = new byte[finalArray.length + array.length];

      System.arraycopy(finalArray, 0, tempArray, 0, finalArray.length);
      System.arraycopy(array, 0, tempArray, finalArray.length, array.length);

      finalArray = tempArray;
    }

    return finalArray;
  }
}