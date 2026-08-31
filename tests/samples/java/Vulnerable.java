import java.security.MessageDigest;
import java.sql.Statement;
import javax.servlet.http.HttpServletResponse;
class Vulnerable {
    void run(Statement statement, String userInput, HttpServletResponse response) throws Exception {
        statement.executeQuery("SELECT * FROM users WHERE name=" + userInput);
        Runtime.getRuntime().exec(userInput);
        String password = "secret";
        MessageDigest.getInstance("MD5");
        response.getWriter().print(userInput);
        new FileInputStream("/srv/data/" + userInput);
        upload.transferTo(new File("/srv/uploads/" + upload.getOriginalFilename()));
        DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(xmlInput);
    }
}
