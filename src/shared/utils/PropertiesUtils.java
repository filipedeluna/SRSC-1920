package shared.utils;

import shared.errors.properties.PropertiesException;
import shared.errors.properties.PropertiesFileErrorException;
import shared.errors.properties.PropertiesFileNotFoundException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

public abstract class PropertiesUtils {
  public static Properties load(String path) throws PropertiesException {
    try {
      Properties properties = new Properties();
      properties.load(new FileInputStream(path));

      return properties;
    } catch (FileNotFoundException e) {
      throw new PropertiesFileNotFoundException(path);
    } catch (IOException e) {
      throw new PropertiesFileErrorException(path);
    }
  }
}
