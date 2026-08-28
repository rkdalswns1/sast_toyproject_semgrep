import java.security.MessageDigest;
import java.sql.Statement;
class Vulnerable {
    void run(Statement statement, String userInput) throws Exception {
        statement.executeQuery("SELECT * FROM users WHERE name=" + userInput);
        Runtime.getRuntime().exec(userInput);
        String password = "secret";
        MessageDigest.getInstance("MD5");
    }
}
