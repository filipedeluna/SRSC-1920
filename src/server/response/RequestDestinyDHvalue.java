package server.response;

public final class RequestDestinyDHvalue extends OkResponseWithNonce  {

  private String dhdentinyvalue;
  private String secdata;
  public RequestDestinyDHvalue(String nonce, String dhv, String sds) {
    super(nonce);
    dhdentinyvalue= dhv;
    secdata= sds;
  }

  public String getDhdentinyvalue() {
    return dhdentinyvalue;
  }

  public String getSecdata() {
    return secdata;
  }
}
