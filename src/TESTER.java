import shared.utils.crypto.util.KeySizeFinder;

import java.security.Provider;
import java.security.Security;

public class TESTER {

  public static void main(String[] args) throws Exception {
    System.out.println(KeySizeFinder.findMaxSea("AES/CBC"));


    Provider provider = Security.getProvider("BC");

   // for (Provider.Service service : provider.getServices()) {
      //System.out.println(service.getType() + " " +  service.getAlgorithm());
    //}


    ;
  }
}
