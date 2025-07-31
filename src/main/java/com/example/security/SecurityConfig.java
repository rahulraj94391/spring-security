package com.example.security;

import com.example.security.securitydemo.jwt.AuthEntryPointJwt;
import com.example.security.securitydemo.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    @Autowired
    DataSource dataSource;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authJWTTokenFilter() {
        return new AuthTokenFilter();
    }

    /*@Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests ->
                requests.requestMatchers("/h2-console/**").permitAll()
                        .requestMatchers("/signin").permitAll()
                        .anyRequest().authenticated())
        );

        // Allow H2 console to be accessed without CSRF and frame restrictions
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/h2-console/**"));
        // http.headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()));

        http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler));
        http.sessionManagement(session -> session.sessionCreationPolicy(STATELESS));
        // http.httpBasic(withDefaults());
        http.addFilterBefore(authJWTTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }*/

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                // 1. Disable CSRF, as it's not needed for stateless JWT-based APIs
                .csrf(csrf -> csrf.disable())

                // 2. Define authorization rules
                .authorizeHttpRequests(requests -> requests
                        // 3. Combine public endpoints into a single matcher
                        .requestMatchers("/h2-console/**", "/signin").permitAll()
                        .anyRequest().authenticated()
                )

                // 4. Set session management to stateless
                .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))

                // 5. Add custom JWT filter before the standard authentication filter
                .addFilterBefore(authJWTTokenFilter(), UsernamePasswordAuthenticationFilter.class)

                // 6. (CRITICAL) Allow H2 console to be embedded in a frame
                .headers(headers -> headers
                        .frameOptions(frameOptions -> frameOptions.sameOrigin())
                );

        return http.build();
    }

    /*@Bean
    public UserDetailsService userDetailsService() {
        UserDetails user1 = User
                .withUsername("user1")
                .password(passwordEncoder().encode("password1"))
                .roles("USER")
                .build();
        UserDetails admin = User
                .withUsername("admin")
                .password(passwordEncoder().encode("adminPassword"))
                .roles("ADMIN")
                .build();

        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user1);
        jdbcUserDetailsManager.createUser(admin);
        return jdbcUserDetailsManager;
    }*/

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public CommandLineRunner initData(UserDetailsService userDetailsService) {
        return args -> {
            JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;
            UserDetails user1 = User
                    .withUsername("user1")
                    .password(passwordEncoder().encode("password1"))
                    .roles("USER")
                    .build();
            UserDetails admin = User
                    .withUsername("admin")
                    .password(passwordEncoder().encode("adminPassword"))
                    .roles("ADMIN")
                    .build();

            JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
            jdbcUserDetailsManager.createUser(user1);
            jdbcUserDetailsManager.createUser(admin);
        };
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }
}
