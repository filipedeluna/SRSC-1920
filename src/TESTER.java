import client.utils.FileHelper;
import shared.Pair;

import java.util.ArrayList;
import java.util.Arrays;

public class TESTER {

  public static void main(String[] args) throws Exception {
    //System.out.println(KeySizeFinder.findMaxSea("AES"));


    //Provider provider = Security.getProvider("BC");

    // for (Provider.Service service : provider.getServices()) {
    //System.out.println(service.getType() + " " +  service.getAlgorithm());
    //}


    FileHelper fh = new FileHelper("");

    ArrayList<Pair<String, Integer>> list = fh.parseFileSpec("test1 800, test2 300");

    for (Pair<String, Integer> pair : list)
      System.out.println(pair.getA() + " " + pair.getB());


    byte[] b1 = new byte[]{1, 2, 3, 3, 4, 4, 1, 42, 1, 41, 41, 41, 2};
    byte[] b2 = new byte[]{};


    b2 = Arrays.copyOfRange(b1, 0, 5);

    System.out.println(b1.length + " " + b2.length);

  }
}
