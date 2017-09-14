package hello.security;

import javax.servlet.http.Cookie;

public class HttpCookieArray {

	private final Cookie[] cookies;

	public HttpCookieArray(Cookie[] cookies) {
		super();
		this.cookies = cookies;
	}

	public HttpCookie cookie(String name) {
		for (Cookie cookie : cookies) {
    		if (name.equals(cookie.getName())) {
    			return new HttpCookie(cookie);
    		}
    	}
		throw new RuntimeException("Cookie " + name + " was not found in array");
	}

	public boolean contains(String name) {
		for (Cookie cookie : cookies) {
    		if (name.equals(cookie.getName())) {
    			return true;
    		}
    	}
		return false;
	}
	
}
