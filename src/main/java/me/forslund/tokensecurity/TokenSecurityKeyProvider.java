package me.forslund.tokensecurity;

import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;

@Component
public interface TokenSecurityKeyProvider {
    Optional<RSAPublicKey> getPublicKey();
    Optional<RSAPrivateKey> getPrivateKey();
    void saveKeyPairToDisk();
}
