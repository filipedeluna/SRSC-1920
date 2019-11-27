import com.google.gson.Gson;

public class TESTER {

  public static void main(String[] args) {
    TestGson obj = new TestGson("NoRefFoundRandomError");
    Gson gson = new Gson();
    String json = gson.toJson(obj);

    System.out.println(json);
  }
}
