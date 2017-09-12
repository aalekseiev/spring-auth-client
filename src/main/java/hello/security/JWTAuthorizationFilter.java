package hello.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class JWTAuthorizationFilter extends OncePerRequestFilter {
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private boolean ignoreFailure = false;

    private PublicKey publicKey;

    public JWTAuthorizationFilter(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {
        String tokenValue = Optional
                .ofNullable(WebUtils.getCookie(request, SecurityConstants.JWT_COOKIE_NAME)).map(Cookie::getValue).orElse("");

        // Can be false if cookie value is null
        if (tokenValue == null || tokenValue.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }

        try {
            UsernamePasswordAuthenticationToken authentication = getAuthentication(tokenValue);

            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request, response);
        } catch (ExpiredJwtException expJwt) {
            SecurityContextHolder.clearContext();

            onUnsuccessfulAuthentication(request, response, null);

            if (isIgnoreFailure()) {
                chain.doFilter(request, response);
            }


        }
    }

    protected void onUnsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        redirectStrategy.sendRedirect(request, response, "/refresh_token" + "?redirect_uri=" + request.getRequestURL().toString());
    }

    private UsernamePasswordAuthenticationToken getAuthentication(String token) {
        // parse the token.
        Claims body = Jwts.parser()
                .setSigningKey(publicKey)
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

    public boolean isIgnoreFailure() {
        return ignoreFailure;
    }

    public JWTAuthorizationFilter setIgnoreFailure(boolean ignoreFailure) {
        this.ignoreFailure = ignoreFailure;
        return this;
    }
}