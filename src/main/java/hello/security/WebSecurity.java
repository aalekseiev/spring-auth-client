package hello.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled=true)
public class WebSecurity extends WebSecurityConfigurerAdapter {

	private CsrfTokenRepository jwtCsrfTokenRepository;
	
	@Autowired
	public WebSecurity(CsrfTokenRepository jwtCsrfTokenRepository) {
		this.jwtCsrfTokenRepository = jwtCsrfTokenRepository;
	}
	
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().disable()
        	.csrf()
        	    .csrfTokenRepository(jwtCsrfTokenRepository)
        	    .ignoringAntMatchers("/login")
        .and()
        	.sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .authorizeRequests()
        	.antMatchers(HttpMethod.GET, "/login")
        		.permitAll()
            .anyRequest()
            	.authenticated()
            .and()
            .addFilter(new JWTAuthorizationFilter(authenticationManager()));
    }

    
    
    @Override
	public void configure(org.springframework.security.config.annotation.web.builders.WebSecurity web)
			throws Exception {
    	web.ignoring()
    	// ignore all URLs that start with /resources/ or /static/
    	           .antMatchers("/resources/**", "/static/**", "/login");
	}

	@Bean
    CorsConfigurationSource corsConfigurationSource() {
      final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
      source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
      return source;
    }
}
