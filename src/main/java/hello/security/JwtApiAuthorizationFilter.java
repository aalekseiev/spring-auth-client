package hello.security;

import org.springframework.security.core.AuthenticationException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.PublicKey;

public class JwtApiAuthorizationFilter extends JWTAuthorizationFilter {

    public JwtApiAuthorizationFilter(PublicKey publicKey) {
        super(publicKey);
    }

    @Override
    protected void onUnsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        // Do nothing
    }
}