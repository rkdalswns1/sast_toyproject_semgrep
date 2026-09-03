import java.io.ObjectInputStream;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.sql.Statement;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
class TrustAllCertificates implements X509TrustManager {
    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    public void checkClientTrusted(X509Certificate[] chain, String authType) { }
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
    }
}
class Vulnerable {
    private String[] roles;

    public String[] getRoles() {
        return roles;
    }

    public void setRoles(String[] roles) {
        this.roles = roles;
    }

    void run(Statement statement, String userInput, HttpServletRequest request, HttpServletResponse response) throws Exception {
        statement.executeQuery("SELECT * FROM users WHERE name=" + userInput);
        Runtime.getRuntime().exec(userInput);
        String password = "secret";
        MessageDigest.getInstance("MD5");
        response.getWriter().print(userInput);
        new FileInputStream("/srv/data/" + userInput);
        upload.transferTo(new File("/srv/uploads/" + upload.getOriginalFilename()));
        DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(xmlInput);
        ObjectInputStream stream = new ObjectInputStream(request.getInputStream());
        Object value = stream.readObject();
        String code = request.getParameter("code");
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");
        engine.eval(code);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
    }
}

class VulnerableServlet extends HttpServlet {
    void stopContainer() {
        System.exit(1);
    }
}
