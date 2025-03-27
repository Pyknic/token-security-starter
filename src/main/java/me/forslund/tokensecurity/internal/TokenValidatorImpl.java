package me.forslund.tokensecurity.internal;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import me.forslund.tokensecurity.TokenSecurityKeyProvider;
import me.forslund.tokensecurity.TokenValidator;
import me.forslund.tokensecurity.throwable.JwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNull;

public final class TokenValidatorImpl implements TokenValidator {

    private final static Logger LOGGER = LoggerFactory.getLogger(TokenValidatorImpl.class);

    private final @NonNull TokenSecurityKeyProvider tokenSecurityKeyProvider;
    private final @Nullable String expectedIssuer;
    private final @Nullable String expectedScope;
    private final @Nullable String expectedAudience;

    public TokenValidatorImpl(
            @NonNull TokenSecurityKeyProvider tokenSecurityKeyProvider,
            @Nullable String expectedIssuer,
            @Nullable String expectedScope,
            @Nullable String expectedAudience) {

        this.tokenSecurityKeyProvider = requireNonNull(tokenSecurityKeyProvider);
        this.expectedIssuer   = expectedIssuer;
        this.expectedScope    = expectedScope;
        this.expectedAudience = expectedAudience;
    }

    @Override
    public JWTClaimsSet parse(String token) throws JwtException {
        SignedJWT jwt = parseJWT(token);

        verifyValidSignature(jwt);

        var claims = parseClaims(jwt);
        verifyValidity(claims);
        verifyExpectedIssuer(claims);
        verifyExpectedAudience(claims);
        verifyExpectedScope(claims);
        verifyHasSubject(claims);

        return claims;
    }

    private SignedJWT parseJWT(String token) throws JwtException {
        try {
            return SignedJWT.parse(token);
        } catch (final ParseException ex) {
            LOGGER.error("Failed to parse JWT token in Authorization header: {}", token, ex);
            throw new JwtException(JwtException.Reason.INVALID_TOKEN, ex);
        }
    }

    private void verifyValidSignature(SignedJWT jwt) throws JwtException {
        var publicKey = tokenSecurityKeyProvider.getPublicKey().orElseThrow(() -> new RuntimeException(
            "Public key for JWT verification has not been set. Make sure to set property 'jwt.publicKey'!"));

        JWSHeader header = jwt.getHeader();
        if (!JWSAlgorithm.RS256.equals(header.getAlgorithm())) {
            LOGGER.error("Unsupported JWS algorithm: {}", header.getAlgorithm());
            throw new JwtException(JwtException.Reason.BAD_ALGORITH);
        }

        RSASSAVerifier verifier = new RSASSAVerifier(publicKey);
        try {
            if (!jwt.verify(verifier)) {
                LOGGER.error("Invalid token RSA signature.");
                throw new JwtException(JwtException.Reason.INVALID_SIGNATURE);
            }
        } catch (final JOSEException ex) {
            LOGGER.error("Exception trying to verify JWS signature.", ex);
            throw new JwtException(JwtException.Reason.INTERNAL_ERROR);
        }
    }

    private JWTClaimsSet parseClaims(SignedJWT jwt) throws JwtException {
        try {
            return requireNonNull(jwt.getJWTClaimsSet());
        } catch (final ParseException ex) {
            LOGGER.error("Failed to extract claims from JWT token in Authorization header.", ex);
            throw new JwtException(JwtException.Reason.INVALID_CLAIMS);
        }
    }

    private void verifyValidity(JWTClaimsSet claims) throws JwtException {
        Instant now = Instant.now();
        Instant expires = claims.getExpirationTime().toInstant();
        if (expires.isBefore(now)) {
            LOGGER.error("JWT token expired at {}, which was {} ago",
                claims.getExpirationTime(),
                Duration.between(expires, now));
            throw new JwtException(JwtException.Reason.EXPIRED_TOKEN);
        }

        boolean valid = Optional.ofNullable(claims.getNotBeforeTime())
            .map(Date::toInstant)
            .map(notValidBefore -> notValidBefore.isBefore(now))
            .orElse(true);

        if (!valid) {
            LOGGER.error("JWT token not valid until {}, which is in {}",
                claims.getNotBeforeTime(),
                Duration.between(now, claims.getNotBeforeTime().toInstant()));
            throw new JwtException(JwtException.Reason.TOKEN_NOT_YET_VALID);
        }
    }

    private void verifyExpectedIssuer(JWTClaimsSet claims) throws JwtException {
        if (!StringUtils.hasText(expectedIssuer)) return;

        var actualIssuer = claims.getIssuer();
        if (expectedIssuer.equals(actualIssuer)) return;

        LOGGER.error("Expected issuer '{}' did not match actual issuer '{}'", expectedIssuer, actualIssuer);
        throw new JwtException(JwtException.Reason.INVALID_ISSUER);
    }

    private void verifyExpectedAudience(JWTClaimsSet claims) throws JwtException {
        if (expectedAudience == null || expectedAudience.isEmpty()) return;

        var actualAudience = claims.getAudience();
        if (actualAudience == null) {
            LOGGER.error("Missing required audience claim in token.");
            throw new JwtException(JwtException.Reason.INVALID_AUDIENCE);
        }

        if (!actualAudience.contains(expectedAudience)) {
            LOGGER.error("Expected audience '{}' was not present in actual audience {}", expectedAudience, actualAudience);
            throw new JwtException(JwtException.Reason.INVALID_AUDIENCE);
        }
    }

    private void verifyExpectedScope(JWTClaimsSet claims) throws JwtException {
        if (!StringUtils.hasText(expectedScope)) return;

        try {
            var spaceSeparated = claims.getStringClaim("scope");
            if (spaceSeparated == null) {
                LOGGER.error("Missing required 'scope' claim in JWT token.");
                throw new JwtException(JwtException.Reason.INVALID_SCOPE);
            }

            if (Stream.of(spaceSeparated.split("\\s+"))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .noneMatch(expectedScope::equals)) {

                LOGGER.error("Missing required scope in JWT token. Expected '{}' but got '{}'.",
                    expectedScope, spaceSeparated);
                throw new JwtException(JwtException.Reason.INVALID_SCOPE);
            }

        } catch (final ParseException e) {
            LOGGER.error("Failed to parse the scope claim in JWT token.");
            throw new JwtException(JwtException.Reason.INVALID_SCOPE);
        }
    }

    private void verifyHasSubject(JWTClaimsSet claims) throws JwtException {
        var subject = claims.getSubject();
        if (!StringUtils.hasText(subject)) {
            LOGGER.error("Missing expected subject claim in JWT token.");
            throw new JwtException(JwtException.Reason.INVALID_SUBJECT);
        }
    }
}
