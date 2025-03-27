package me.forslund.tokensecurity;

import com.nimbusds.jwt.JWTClaimsSet;
import me.forslund.tokensecurity.throwable.JwtException;

public interface TokenValidator {

    JWTClaimsSet parse(String token) throws JwtException;

}
