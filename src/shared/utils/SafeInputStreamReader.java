package shared.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

public final class SafeInputStreamReader extends InputStreamReader {
  private static final long MEGA_BYTE = 1024L * 1024L; // 1 MB

  private long bytesRead;
  private long maxBufferSize;

  // This class makes it so users can't send HUGE files and DOS
  public SafeInputStreamReader(InputStream in, int maxBufferSizeInMB) {
    super(in, StandardCharsets.UTF_8);

    maxBufferSize = MEGA_BYTE * maxBufferSizeInMB;
    bytesRead = 0;
  }

  @Override
  public int read() throws IOException {
    return readBytes(super.read());
  }

  @Override
  public int read(char[] var1) throws IOException {
    return readBytes(super.read(var1, 0, var1.length));
  }

  @Override
  public int read(char[] var1, int var2, int var3) throws IOException {
    return readBytes(super.read(var1, var2, var3));
  }

  @Override
  public synchronized void reset() throws IOException {
    super.reset();
    bytesRead = 0;
  }

  /*
    UTILS
  */
  private int readBytes(int lastRead) throws IOException {
    bytesRead += lastRead;

    if (bytesRead > maxBufferSize)
      throw new IOException("Max file size passed.");

    return lastRead;
  }

}
