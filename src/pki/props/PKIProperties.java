package pki.props;

import shared.PropertyType;
import shared.errors.properties.*;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

public class PKIProperties extends Properties {

  public PKIProperties(String path) throws PropertyException {
    super();

    try {
      this.load(new FileInputStream(path));
    } catch (FileNotFoundException e) {
      throw new PropertyFileNotFoundException(path);
    } catch (IOException e) {
      throw new PropertyFileErrorException(path);
    }
  }

  public String getString(PKIProperty prop) throws PropertyException {
    if (prop.type() != PropertyType.STRING)
      throw new InvalidPropertyTypeException(prop.val(), "string");

    return getValue(prop);
  }

  public int getInt(PKIProperty prop) throws PropertyException {
    if (prop.type() != PropertyType.INT)
      throw new InvalidPropertyTypeException(prop.val(), "int");

    String value = getValue(prop);

    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException e) {
      throw new InvalidPropertyValueException(prop.val());
    }
  }

  public boolean getBoolean(PKIProperty prop) throws PropertyException {
    if (prop.type() != PropertyType.BOOL)
      throw new InvalidPropertyTypeException(prop.val(), "bool");

    String value = getValue(prop);

    if (!value.equals("true") && !value.equals("false"))
      throw new InvalidPropertyValueException(prop.val());

    return Boolean.parseBoolean(value);
  }

  public String[] getStringArray(PKIProperty prop) throws PropertyException {
    if (prop.type() != PropertyType.STRING_ARRAY)
      throw new InvalidPropertyTypeException(prop.val(), "string array");

    String value = getValue(prop);

    return value.split(",");
  }

  private String getValue(PKIProperty prop) throws PropertyException {
    String value = getProperty(prop.val());

    if (value == null)
      throw new PropertyNotFoundException(prop.val());

    return value;
  }
}
