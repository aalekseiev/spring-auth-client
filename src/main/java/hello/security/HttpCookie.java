package hello.security;

import javax.servlet.http.Cookie;

public class HttpCookie {

	private Cookie cookie;

	public HttpCookie(Cookie cookie) {
		this.cookie = cookie;
	}

	public String value() {
    	return cookie.getValue();
	}
}
