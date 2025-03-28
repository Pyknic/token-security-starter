package me.forslund.tokensecurity.internal;

import me.forslund.tokensecurity.TokenSecurityKeyProvider;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import static java.util.Objects.requireNonNull;

@Component
@ConditionalOnProperty(name = "TokenSecurityProperties", havingValue = "true")
public class TokenSecurityKeyGenerator implements ApplicationRunner {

    private final TokenSecurityKeyProvider tokenSecurityKeyProvider;

    public TokenSecurityKeyGenerator(TokenSecurityKeyProvider tokenSecurityKeyProvider) {
        this.tokenSecurityKeyProvider = requireNonNull(tokenSecurityKeyProvider);
    }

    @Override
    public void run(ApplicationArguments args) {
        tokenSecurityKeyProvider.saveKeyPairToDisk();
    }
}
