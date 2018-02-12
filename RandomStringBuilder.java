import java.util.Random;

public class RandomStringBuilder {

  public static void main(String[] args) {
    StringBuilder printString = new StringBuilder();
    printString.append("{\n");

    String stringSize = args[0];

    for (int i = 0; i < 1000; i++) {
      printString.append("\"").append(getSaltString(Integer.valueOf(stringSize))).append("\", ");
      if ((i+1)%10==0)
        printString.append("\n");
    }
    printString.append("};");
    System.out.println(printString);
  }

  public static String getSaltString(int stringSize) {
    String SALTCHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
    StringBuilder salt = new StringBuilder();
    Random rnd = new Random();
    while (salt.length() < stringSize) { // length of the random string.
      int index = (int) (rnd.nextFloat() * SALTCHARS.length());
      salt.append(SALTCHARS.charAt(index));
    }
    String saltStr = salt.toString();
    return saltStr;
  }
}