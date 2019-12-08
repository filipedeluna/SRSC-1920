package shared.parameters;

import shared.utils.Utils;

import java.util.LinkedHashMap;
import java.util.Map.Entry;

public final class ServerParameterMap extends LinkedHashMap<String, String> {
  public ServerParameterMap() {
    super();
  }

  public void put(ServerParameterType type, String value) {
    put(type.dbName(), value);
  }

  public String getParameterValue(ServerParameterType type) {
    return get(type.dbName());
  }

  public byte[] getAllParametersBytes() {
    byte[] resultArray = new byte[1];

    for (Entry<String, String> entry : entrySet()) {
      // Make sure we're not getting the bytes from the signature
      if (entry.getKey().equals(ServerParameterType.PARAM_SIG.dbName()))
        continue;

      resultArray = Utils.joinByteArrays(resultArray, entry.getValue().getBytes());
    }

    return resultArray;
  }
}

