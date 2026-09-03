import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.Arrays;
import javax.net.ssl.TrustManagerFactory;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
class Safe {
    private String[] roles;

    public String[] getRoles() {
        return roles.clone();
    }

    public void setRoles(String[] roles) {
        this.roles = Arrays.copyOf(roles, roles.length);
    }

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
        String operation = request.getParameter("operation");
        allowedOperations.get(operation).run();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
    }
}

class SafeServlet extends HttpServlet {
    void rejectRequest() {
        throw new IllegalArgumentException("invalid request");
    }
}
