package pki.props;

import shared.PropertyType;
import shared.errors.properties.*;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class PKIProperties extends Properties {

  public PKIProperties(String path) throws PropertyException {
    super();

    try {
      this.load(new FileInputStream(path));
    } catch (java.io.FileNotFoundException e) {
      throw new FileNotFoundException(path);
    } catch (IOException e) {
      throw new FileErrorException(path);
    }
  }

  public String getString(PKIProperty prop) throws PropertyException {
    if (prop.type() != PropertyType.STRING)
      throw new InvalidTypeException(prop.val(), "string");

    return getValue(prop);
  }

  public int getInt(PKIProperty prop) throws PropertyException {
    if (prop.type() != PropertyType.INT)
      throw new InvalidTypeException(prop.val(), "int");

    String value = getValue(prop);

    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException e) {
      throw new InvalidValueException(prop.val());
    }
  }

  public boolean getBoolean(PKIProperty prop) throws PropertyException {
    if (prop.type() != PropertyType.BOOL)
      throw new InvalidTypeException(prop.val(), "bool");

    String value = getValue(prop);

    if (!value.equals("true") && !value.equals("false"))
      throw new InvalidValueException(prop.val());

    return Boolean.parseBoolean(value);
  }

  public String[] getStringArray(PKIProperty prop) throws PropertyException {
    if (prop.type() != PropertyType.STRING_ARRAY)
      throw new InvalidTypeException(prop.val(), "string array");

    String value = getValue(prop);

    return value.split(",");
  }

  private String getValue(PKIProperty prop) throws PropertyException {
    String value = getProperty(prop.val());

    if (value == null)
      throw new NotFoundException(prop.val());

    return value;
  }
}
