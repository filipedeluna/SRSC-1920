import shared.utils.Utils;

import javax.rmi.CORBA.Util;

public class TESTER {

  public static void main(String[] args) {
    byte[] arr1 = new byte[]{1};
    byte[] arr2 = new byte[]{2};
    byte[] arr3 = new byte[]{3};
    byte[] arr4 = new byte[]{4};
    byte[] arr5 = new byte[]{5};

    System.out.println(
        Utils.joinByteArrays(
            arr1,
            arr2,
            arr3,
            arr4,
            arr5
        ).length
    );
  }
}
