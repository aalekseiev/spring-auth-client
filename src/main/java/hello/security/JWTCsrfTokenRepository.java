package hello.security;

import java.security.PublicKey;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;

@Component
public class JWTCsrfTokenRepository implements CsrfTokenRepository {

    static final String DEFAULT_CSRF_TOKEN_ATTR_NAME = "CSRFConfig".concat(".CSRF_TOKEN");

    private static final Logger LOG = LoggerFactory.getLogger(JWTCsrfTokenRepository.class);

    private final PublicKey publicKey;
    
    @Autowired
    public JWTCsrfTokenRepository(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public CsrfToken generateToken(HttpServletRequest request) {
    	return new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "dummy-csrf-value");
    }

    @Override
    public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
    	LOG.warn("Don't know how to save token because this is not a UAA server");
    }

    @Override
    public CsrfToken loadToken(HttpServletRequest request) {
    	HttpCookieArray cookieArray = new HttpCookieArray(request.getCookies());
		
    	if (!cookieArray.contains(SecurityConstants.JWT_COOKIE_NAME) || "GET".equals(request.getMethod())) {
            return null;
        }
    	
    	HttpCookie cookie = cookieArray.cookie(SecurityConstants.JWT_COOKIE_NAME);
    	
    	String jwtString = cookie.value();
    	try {
    		Jws<Claims> parseClaimsJws = Jwts.parser()
                    .setSigningKey(publicKey)
    				.parseClaimsJws(jwtString);
    		
    		String csrfTokenString = parseClaimsJws.getBody().get("xsrfToken", String.class);
            return new DefaultCsrfToken(SecurityConstants.CSRF_TOKEN_HEADER,
            							SecurityConstants.CSRF_TOKEN_HEADER,
            							csrfTokenString);
    	} catch (SignatureException e) {
    		throw new RuntimeException("Failed to parse JWT in JWTCsrfTokenRepository", e);
    	}
    	
    	
    }
}