import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import javax.net.ssl.TrustManagerFactory;
import javax.servlet.http.HttpServletRequest;
class Safe {
    void run(Connection connection, String userInput, HttpServletRequest request) throws Exception {
        PreparedStatement statement = connection.prepareStatement("SELECT * FROM users WHERE name=?");
        statement.setString(1, userInput);
        new ProcessBuilder("echo", userInput).start();
        String password = System.getenv("APP_PASSWORD");
        MessageDigest.getInstance("SHA-256");
        new FileInputStream(new File("/srv/data", new File(userInput).getName()));
        upload.transferTo(new File("/srv/uploads", generatedName));
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.newDocumentBuilder().parse(xmlInput);
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        String payload = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }
}
