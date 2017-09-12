package hello.security;

public class SecurityConstants {
	public static final String SECRET = "SecretKeyToGenJWTs";
    public static final long EXPIRATION_TIME = 600_000; // 10 minutes
    public static final String JWT_TOKEN_PREFIX = "Bearer ";
    public static final String JWT_COOKIE_NAME = "Authorization";
    public static final String SIGN_UP_URL = "/users/sign-up";
    
    public static final String CSRF_TOKEN_HEADER = "XSRF-TOKEN";
}
