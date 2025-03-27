package me.forslund.tokensecurity;

import me.forslund.tokensecurity.filters.AuthorizationHeaderFilter;
import me.forslund.tokensecurity.filters.LoginFilter;
import me.forslund.tokensecurity.filters.LogoutFilter;
import me.forslund.tokensecurity.filters.RefreshTokenFilter;
import me.forslund.tokensecurity.internal.JwtTokenService;
import me.forslund.tokensecurity.internal.TokenSecurityKeyGenerator;
import me.forslund.tokensecurity.internal.TokenSecurityKeyProviderImpl;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
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
    LoginFilter.class,
    TokenSecurityKeyGenerator.class
})
@EnableConfigurationProperties(JwtProperties.class)
public class TokenSecurityAutoConfiguration {

    @Bean
    public TokenSecurityKeyProvider tokenSecurityKeyProvider(JwtProperties props) {
        return new TokenSecurityKeyProviderImpl(props);
    }
}
