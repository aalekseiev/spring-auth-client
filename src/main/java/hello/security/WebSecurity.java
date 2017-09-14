package hello.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.security.PublicKey;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled=true)
public class WebSecurity extends WebSecurityConfigurerAdapter {

    @Configuration
    @Order(2)
    public static class MvcSecurity extends WebSecurityConfigurerAdapter {

        private CsrfTokenRepository jwtCsrfTokenRepository;
        private PublicKey publicKey;

        @Autowired
        public MvcSecurity(CsrfTokenRepository jwtCsrfTokenRepository, PublicKey publicKey) {
            this.jwtCsrfTokenRepository = jwtCsrfTokenRepository;
            this.publicKey = publicKey;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .cors().disable()
                    .csrf()
                        .csrfTokenRepository(jwtCsrfTokenRepository)
                        .ignoringAntMatchers("/login")
                    .and()
                    .sessionManagement()
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                    .authorizeRequests()
                        .antMatchers(HttpMethod.GET, "/login").permitAll()
                    .anyRequest()
                        .authenticated()
                    .and()
                    .addFilterBefore(new JWTAuthorizationFilter(publicKey), BasicAuthenticationFilter.class);
        }



        @Override
        public void configure(org.springframework.security.config.annotation.web.builders.WebSecurity web)
                throws Exception {
            web.ignoring()
                    // ignore all URLs that start with /resources/ or /static/
                    .antMatchers("/resources/**", "/static/**", "/login", "/refresh_token", "/favicon.ico");
        }

        @Bean
        CorsConfigurationSource corsConfigurationSource() {
            final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
            source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
            return source;
        }
    }

    @Configuration
    @Order(1)
    public static class ApiSecurity extends WebSecurityConfigurerAdapter {
        private PublicKey publicKey;

        @Autowired
        public ApiSecurity(PublicKey publicKey) {
            this.publicKey = publicKey;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            JWTAuthorizationFilter filter = new JwtApiAuthorizationFilter(publicKey);
            filter.setIgnoreFailure(true);
            http
                    .antMatcher("/tasks")
                    .authorizeRequests().anyRequest().authenticated()
                    .and()
                    .addFilterBefore(filter, BasicAuthenticationFilter.class);
        }
    }

}
