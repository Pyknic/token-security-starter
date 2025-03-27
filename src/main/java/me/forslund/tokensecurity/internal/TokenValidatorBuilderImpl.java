package me.forslund.tokensecurity.internal;

import me.forslund.tokensecurity.TokenSecurityKeyProvider;
import me.forslund.tokensecurity.TokenValidator;
import me.forslund.tokensecurity.TokenValidatorBuilder;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

import static java.util.Objects.requireNonNull;

public final class TokenValidatorBuilderImpl implements TokenValidatorBuilder {

    private final TokenSecurityKeyProvider tokenSecurityKeyProvider;
    private @Nullable String expectedIssuer;
    private @Nullable String expectedScope;
    private @Nullable String expectedAudience;

    public TokenValidatorBuilderImpl(@NonNull TokenSecurityKeyProvider tokenSecurityKeyProvider) {
        this.tokenSecurityKeyProvider = requireNonNull(tokenSecurityKeyProvider);
    }

    @Override
    public TokenValidatorBuilder withIssuer(String expectedIssuer) {
        this.expectedIssuer = expectedIssuer;
        return this;
    }

    @Override
    public TokenValidatorBuilder withAudience(String expectedAudience) {
        this.expectedAudience = expectedAudience;
        return this;
    }

    @Override
    public TokenValidatorBuilder withScope(String expectedScope) {
        this.expectedScope = expectedScope;
        return this;
    }

    @Override
    public TokenValidator build() {
        return new TokenValidatorImpl(tokenSecurityKeyProvider, expectedIssuer, expectedScope, expectedAudience);
    }
}
