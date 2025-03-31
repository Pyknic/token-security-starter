package me.forslund.tokensecurity.internal;

import me.forslund.tokensecurity.filters.AuthorizationHeaderFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

import static java.util.Objects.requireNonNull;

public class TokenSecurityConfigurer extends AbstractHttpConfigurer<TokenSecurityConfigurer, HttpSecurity> implements ApplicationContextAware {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenSecurityConfigurer.class);

    private AuthorizationHeaderFilter filter;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        LOGGER.debug("Setting AuthorizationHeaderFilter in TokenSecurityConfigurer from application context");
        this.filter = requireNonNull(applicationContext.getBean(AuthorizationHeaderFilter.class));
    }

    @Override
    public void init(HttpSecurity builder) throws Exception {}

    @Override
    public void configure(HttpSecurity http) throws Exception {
        LOGGER.debug("Configuring AuthorizationHeaderFilter in SecurityFilterChain");
        http.addFilterBefore(filter, AnonymousAuthenticationFilter.class);
    }
}
