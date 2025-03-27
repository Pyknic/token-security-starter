package me.forslund.tokensecurity;

import me.forslund.tokensecurity.filters.AuthorizationHeaderFilter;
import me.forslund.tokensecurity.filters.LoginFilter;
import me.forslund.tokensecurity.filters.LogoutFilter;
import me.forslund.tokensecurity.filters.RefreshTokenFilter;
import me.forslund.tokensecurity.internal.JwtTokenService;
import me.forslund.tokensecurity.internal.TokenSecurityKeyProviderImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;

@Configuration
@Import({
    JwtTokenService.class,
    AuthorizationHeaderFilter.class,
    RefreshTokenFilter.class,
    LogoutFilter.class,
    LoginFilter.class
})
public class TokenSecurityAutoConfiguration {

    @Bean
    public TokenSecurityKeyProvider tokenSecurityKeyProvider(Environment environment) {
        return new TokenSecurityKeyProviderImpl(environment);
    }
}
