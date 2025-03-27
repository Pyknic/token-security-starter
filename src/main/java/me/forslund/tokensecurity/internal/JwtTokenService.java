package me.forslund.tokensecurity.internal;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import me.forslund.tokensecurity.TokenSecurityKeyProvider;
import me.forslund.tokensecurity.filters.RefreshTokenFilter;
import me.forslund.tokensecurity.throwable.JwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.stream.Stream;

import static java.util.stream.Collectors.joining;

@Component
public class JwtTokenService {

    private final static Logger LOGGER = LoggerFactory.getLogger(JwtTokenService.class);

    private final TokenSecurityKeyProvider tokenSecurityKeyProvider;

    private @Value("${jwt.issuer:localhost}") String expectedIssuer;
    private @Value("${jwt.audience:localhost}") String expectedAudience;
    private @Value("${jwt.accessToken.validity:PT10M}") Duration accessTokenValidity;
    private @Value("${jwt.refreshToken.validity:PT16H}") Duration refreshTokenValidity;

    @Autowired
    public JwtTokenService(TokenSecurityKeyProvider tokenSecurityKeyProvider) {
        this.tokenSecurityKeyProvider = tokenSecurityKeyProvider;
    }

    public SignedJWT createAccessToken(UserDetails userDetails) throws JwtException {
        return createToken(userDetails, true);
    }

    public SignedJWT createRefreshToken(UserDetails userDetails) throws JwtException {
        return createToken(userDetails, false);
    }

    private SignedJWT createToken(UserDetails userDetails, boolean isAccessToken) throws JwtException {
        var privateKey = tokenSecurityKeyProvider.getPrivateKey().orElseThrow(() -> new RuntimeException(
            "Private key for JWT signing has not been set. Make sure to set property 'jwt.privateKey'!"));

        var claimsBuilder = new JWTClaimsSet.Builder()
            .subject(userDetails.getUsername())
            .issuer(expectedIssuer)
            .audience(expectedAudience)
            .issueTime(Date.from(Instant.now()))
            .expirationTime(Date.from(Instant.now().plus(isAccessToken ? accessTokenValidity : refreshTokenValidity)));

        var scopes = Stream.concat(
            userDetails.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority),
            Stream.of("refresh").filter(s -> !isAccessToken)
        ).filter(StringUtils::hasText).collect(joining(" "));

        if (StringUtils.hasText(scopes)) {
            claimsBuilder.claim("scope", scopes);
        }

        var claims = claimsBuilder.build();

        SignedJWT signedJWT = new SignedJWT(
            new JWSHeader(JWSAlgorithm.RS256), // RS256 is one of the algorithms for RSA
            claims
        );

        final RSASSASigner signer = new RSASSASigner(privateKey);
        try {
            signedJWT.sign(signer);
        } catch (final JOSEException ex) {
            LOGGER.error("JWT token signing failed.", ex);
            throw new JwtException(JwtException.Reason.INTERNAL_ERROR, ex);
        }

        return signedJWT;
    }

}
