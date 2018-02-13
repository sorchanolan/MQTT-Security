import java.util.Random;

public class RandomStringBuilder {

  public static void main(String[] args) {
    StringBuilder printString = new StringBuilder();
    printString.append("{\n");

    int stringSize = Integer.valueOf(args[0]);
    int numberOfStrings = Integer.valueOf(args[1]);

    for (int i = 0; i < numberOfStrings; i++) {
      printString.append("\"").append(getSaltString(stringSize)).append("\", ");
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