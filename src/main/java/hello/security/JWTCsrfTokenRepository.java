package hello.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.UUID;

@Component
public class JWTCsrfTokenRepository implements CsrfTokenRepository {

    static final String DEFAULT_CSRF_TOKEN_ATTR_NAME = "CSRFConfig".concat(".CSRF_TOKEN");

    private static final Logger LOG = LoggerFactory.getLogger(JWTCsrfTokenRepository.class);

    public JWTCsrfTokenRepository() {}

    @Override
    public CsrfToken generateToken(HttpServletRequest request) {
//        String id = UUID.randomUUID().toString().replace("-", "");
//        return new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", id);
    	return new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "dummy-csrf-value");
    }

    @Override
    public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
        if (token == null) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.removeAttribute(DEFAULT_CSRF_TOKEN_ATTR_NAME);
            }
        }
        else {
            HttpSession session = request.getSession();
            session.setAttribute(DEFAULT_CSRF_TOKEN_ATTR_NAME, token);
        }
    }

    @Override
    public CsrfToken loadToken(HttpServletRequest request) {
    	
    	String jwtHeader = null;
    	if (request.getCookies() != null) {
	    	for (Cookie cookie : request.getCookies()) {
	    		if (SecurityConstants.JWT_HEADER_STRING.equals(cookie.getName())) {
	    			jwtHeader = cookie.getValue();
	    			break;
	    		}
	    	}
    	}

    	if (jwtHeader == null || "GET".equals(request.getMethod())) {
            return null;
        }
    	String jwtString = jwtHeader;
    	try {
    		Jws<Claims> parseClaimsJws = Jwts.parser()
    				.setSigningKey(SecurityConstants.SECRET)
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