package hello.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    public JWTAuthorizationFilter(AuthenticationManager authManager) {
        super(authManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {
        String authorizationCookie = null;
    	if (request.getCookies() != null) {
	    	for (Cookie cookie : request.getCookies()) {
	    		if (SecurityConstants.JWT_HEADER_STRING.equals(cookie.getName())) {
	    			authorizationCookie = cookie.getValue();
	    			break;
	    		}
	    	}
    	}

        if (authorizationCookie == null) {
            chain.doFilter(request, res);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = getAuthentication(request);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(request, res);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = null;
    	if (request.getCookies() != null) {
	    	for (Cookie cookie : request.getCookies()) {
	    		if (SecurityConstants.JWT_HEADER_STRING.equals(cookie.getName())) {
	    			token = cookie.getValue();
	    			break;
	    		}
	    	}
    	}
        
        if (token != null) {
            // parse the token.
            Claims body = Jwts.parser()
                    .setSigningKey(SecurityConstants.SECRET)
                    .parseClaimsJws(token.replace(SecurityConstants.JWT_TOKEN_PREFIX, ""))
                    .getBody();
            String user = body.getSubject();
            List<String> permissions = body.get("permissions", List.class);

            if (user != null) {
            	
            	List<GrantedAuthority> authorities = new ArrayList<>();
            	for (String curPermission : permissions) {
					authorities.add(new SimpleGrantedAuthority(curPermission));
				}
            	
                return new UsernamePasswordAuthenticationToken(user, null, authorities);
            }
            return null;
        }
        return null;
    }
}