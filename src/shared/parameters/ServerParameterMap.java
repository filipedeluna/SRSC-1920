package shared.parameters;

import server.errors.parameters.DuplicateParameterException;
import server.errors.parameters.InvalidParameterOrderException;
import server.errors.parameters.ParameterException;
import shared.Pair;
import shared.utils.CryptUtil;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map.Entry;

public final class ServerParameterMap extends LinkedHashMap<String, Pair<Integer, String>> {
  public ServerParameterMap() {
    super();
  }

  public void put(ServerParameterType type, String value) throws ParameterException {
    put(size(), type.dbName(), value);
  }

  public void put(int id, String name, String value) throws ParameterException {
    if (containsKey(name))
      throw new DuplicateParameterException(name);

    put(name, new Pair<>(id, value));
  }

  public String getParameterValue(ServerParameterType type) {
    return get(type.dbName()).getB();
  }

  public byte[] getAllParametersBytes() throws IOException, ParameterException {
    byte[] resultArray = new byte[1];
    int count = 0;
    Pair<Integer, String> pair;

    for (Entry<String, Pair<Integer, String>> entry : entrySet()) {
      // Make sure we're not getting the bytes from the signature
      if (entry.getKey().equals(ServerParameterType.PARAM_SIG.dbName()))
        continue;

      pair = entry.getValue();

      if (pair.getA() != count++)
        throw new InvalidParameterOrderException();

      resultArray = CryptUtil.joinByteArrays(resultArray, pair.getB().getBytes());
    }

    return resultArray;
  }
}

