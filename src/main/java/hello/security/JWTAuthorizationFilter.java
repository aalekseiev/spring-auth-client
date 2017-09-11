package hello.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.util.WebUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    public JWTAuthorizationFilter(AuthenticationManager authManager) {
        super(authManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {
        String tokenValue = Optional
                .ofNullable(WebUtils.getCookie(request, SecurityConstants.JWT_HEADER_STRING)).map(Cookie::getValue).orElse("");

        // Can be false if cookie value is null
        if (tokenValue == null || tokenValue.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = null;
        try {
            authentication = getAuthentication(tokenValue);
        } catch (ExpiredJwtException expJwt) {
            SecurityContextHolder.clearContext();

            redirectStrategy.sendRedirect(request,response, "/refresh_token" + "?redirect_uri=" + request.getRequestURL().toString());
            return;
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(String token) {
        UsernamePasswordAuthenticationToken result = null;

        // parse the token.
        Claims body = Jwts.parser()
                .setSigningKey(SecurityConstants.SECRET)
                .parseClaimsJws(token.replace(SecurityConstants.JWT_TOKEN_PREFIX, "")).getBody();
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
}