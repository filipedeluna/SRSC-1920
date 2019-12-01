package shared.utils;

import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import shared.errors.request.InvalidFormatException;
import shared.errors.request.InvalidValueTypeException;
import shared.errors.request.MissingValueException;
import shared.errors.request.RequestException;

import java.util.ArrayList;

public abstract class GsonUtils {
  public static String getString(JsonObject obj, String val) throws RequestException {
    try {
      return getElement(obj, val).getAsString();
    } catch (ClassCastException | IllegalStateException e) {
      throw new InvalidValueTypeException(val, "string");
    }
  }

  public static int getInt(JsonObject obj, String val) throws RequestException {
    try {
      return getElement(obj, val).getAsInt();
    } catch (ClassCastException | IllegalStateException e) {
      throw new InvalidValueTypeException(val, "int");
    }
  }

  public static boolean getBool(JsonObject obj, String val) throws RequestException {
    try {
      return getElement(obj, val).getAsBoolean();
    } catch (ClassCastException | IllegalStateException e) {
      throw new InvalidValueTypeException(val, "boolean");
    }
  }

  public static ArrayList<String> getStringList(JsonObject obj, String val) throws RequestException {
    try {
      ArrayList<String> list = new ArrayList<>();
      JsonArray array = getElement(obj, val).getAsJsonArray();

      for (int i = 0; i < array.size(); i++) {
        list.add(array.get(i).getAsString());
      }

      return list;
    } catch (ClassCastException | IllegalStateException e) {
      throw new InvalidValueTypeException(val, "string array");
    }
  }

  public static ArrayList<Integer> getIntList(JsonObject obj, String val) throws RequestException {
    try {
      ArrayList<Integer> list = new ArrayList<>();
      JsonArray array = getElement(obj, val).getAsJsonArray();

      for (int i = 0; i < array.size(); i++) {
        list.add(array.get(i).getAsInt());
      }

      return list;
    } catch (ClassCastException | IllegalStateException e) {
      throw new InvalidValueTypeException(val, "int array");
    }
  }

  public static ArrayList<Boolean> getBoolList(JsonObject obj, String val) throws RequestException {
    try {
      ArrayList<Boolean> list = new ArrayList<>();
      JsonArray array = getElement(obj, val).getAsJsonArray();

      for (int i = 0; i < array.size(); i++) {
        list.add(array.get(i).getAsBoolean());
      }

      return list;
    } catch (ClassCastException | IllegalStateException e) {
      throw new InvalidValueTypeException(val, "boolean array");
    }
  }

  public static JsonObject getJsonObj(JsonObject obj, String val) throws RequestException {
    try {
      return getElement(obj, val).getAsJsonObject();
    } catch (ClassCastException | IllegalStateException e) {
      throw new InvalidValueTypeException(val, "json object");
    }
  }


  private static JsonElement getElement(JsonObject obj, String val) throws RequestException {
    JsonElement elem = obj.get(val);

    if (elem == null)
      throw new MissingValueException(val);

    return elem;
  }

  public static Gson buildGsonInstance() {
    return new GsonBuilder()
        .serializeNulls()
        .setFieldNamingPolicy(FieldNamingPolicy.IDENTITY)
        .setPrettyPrinting()
        .create();
  }

  public static JsonObject parseRequest(JsonReader reader) throws InvalidFormatException {
    JsonElement data = new JsonParser().parse(reader);

    if (!data.isJsonObject())
      throw new InvalidFormatException();

    return data.getAsJsonObject();
  }
}
