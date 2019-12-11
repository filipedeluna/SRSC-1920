package client.utils;

import shared.Pair;
import shared.utils.Utils;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;

public final class FileHelper {
  private String destinationFolder;

  public FileHelper(String destinationFolder) throws IOException {
    this.destinationFolder = destinationFolder;

    if (!Files.isDirectory(Paths.get(destinationFolder)))
      Files.createDirectory(Paths.get(destinationFolder));
  }

  public ArrayList<ValidFile> getFiles(String... paths) throws IOException {
    ArrayList<ValidFile> list = new ArrayList<>();

    for (String path : paths)
      list.add(getFile(path));

    return list;
  }

  private ValidFile getFile(String path) throws IOException {
    ValidFile file = new ValidFile(path);

    if (!isFileNameValid(file.getName()))
      throw new IOException("File " + path + " does not have a valid name.");

    // Check file exists and is not a directory
    if (!file.exists() || file.isDirectory())
      throw new IOException("File " + path + " does not exist or is a directory.");

    return file;
  }

  public byte[] readFile(ValidFile validFile) throws IOException {
    return Files.readAllBytes(Paths.get(validFile.getPath()));
  }

  public byte[] readAllFiles(ArrayList<ValidFile> validFiles) throws IOException {
    byte[] data = new byte[0];

    for (ValidFile validFile : validFiles)
      data = Utils.joinByteArrays(data, readFile(validFile));

    return data;
  }

  public synchronized void writeFile(String fileName, byte[] data) throws IOException {
    Path filePath = Paths.get(destinationFolder + "/" + fileName);

    // Check destination valid
    //if (Files.isWritable(filePath))
      //throw new IOException("Invalid destination for file: " + filePath.toString());

    // Delete previous file
    if (Files.exists(filePath))
      Files.delete(filePath);

    // write the file
    Files.write(filePath, data);
  }

  public String getFileSpec(ArrayList<ValidFile> validFiles) {
    StringBuilder stringBuilder = new StringBuilder();

    // Build spec for all files
    int counter = 0;
    for (ValidFile validFile : validFiles) {
      counter++;

      stringBuilder.append(validFile.getName());
      stringBuilder.append(" ");
      stringBuilder.append(validFile.length());

      if (counter < validFiles.size())
        stringBuilder.append(", ");
    }

    return stringBuilder.toString();
  }

  public ArrayList<Pair<String, Integer>> parseFileSpec(String spec) throws IOException {
    ArrayList<Pair<String, Integer>> parsedSpecPairs = new ArrayList<>();

    String[] specPairs = spec.trim().split(",");

    String[] splitSpecPair;
    String fileName;
    int fileSize;

    for (String specPair : specPairs) {
      splitSpecPair = specPair.trim().split(" ");

      fileName = splitSpecPair[0];

      if (!isFileNameValid(fileName))
        throw new IOException("Invalid file name " + fileName + " in file spec.");

      try {
        fileSize = Integer.parseInt(splitSpecPair[1]);

        parsedSpecPairs.add(new Pair<>(fileName, fileSize));
      } catch (NumberFormatException e) {
        throw new IOException("Invalid file size in file spec.");
      }
    }
    return parsedSpecPairs;
  }

  /*
    UTILS
  */
  private boolean isFileNameValid(String fileName) {
    // Get name and extension and check they are valid
    String[] trimmedName = fileName.split("\\.");

    if (trimmedName.length == 1)
      return trimmedName[0].length() > 0;

    if (trimmedName.length == 2)
      return trimmedName[0].length() > 0 && trimmedName[1].length() > 0;

    return false;
  }
}
