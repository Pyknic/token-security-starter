package me.forslund.tokensecurity;

import me.forslund.tokensecurity.internal.TokenValidatorBuilderImpl;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

public interface TokenValidatorBuilder {

    static TokenValidatorBuilder create(@NonNull TokenSecurityKeyProvider tokenSecurityKeyProvider) {
        return new TokenValidatorBuilderImpl(tokenSecurityKeyProvider);
    }

    TokenValidatorBuilder withIssuer(@Nullable String expectedIssuer);
    TokenValidatorBuilder withAudience(@Nullable String expectedAudience);
    TokenValidatorBuilder withScope(@Nullable String expectedScope);

    TokenValidator build();

}
