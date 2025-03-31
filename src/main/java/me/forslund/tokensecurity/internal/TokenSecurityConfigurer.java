package me.forslund.tokensecurity.internal;

import me.forslund.tokensecurity.filters.AuthorizationHeaderFilter;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static java.util.Objects.requireNonNull;

public class TokenSecurityConfigurer implements SecurityConfigurer<DefaultSecurityFilterChain, HttpSecurity> {

    private final AuthorizationHeaderFilter filter;

    public TokenSecurityConfigurer(AuthorizationHeaderFilter filter) {
        this.filter = requireNonNull(filter);
    }

    @Override
    public void init(HttpSecurity builder) throws Exception {

    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
    }
}
