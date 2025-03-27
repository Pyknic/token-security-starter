package me.forslund.tokensecurity;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

    /**
     * If true, the JWT RSA key pair will be created the first time the application starts.
     */
    private final boolean bootstrap;

    /**
     * The public RSA key to use when validating JWT access and refresh tokens. Can be any of the following:
     * <ul>
     *     <li>The key itself, inlined and base64-encoded</li>
     *     <li>File path to a pem-file on disk</li>
     *     <li>URL to a pem file publicly accessible on the internet</li>
     * </ul>
     * An empty string is ignored.
     */
    private final String publicKey;

    /**
     * The private RSA key to use when generating JWT access and refresh tokens. Can be any of the following:
     * <ul>
     *     <li>The key itself, inlined and base64-encoded</li>
     *     <li>File path to a pem-file on disk</li>
     *     <li>URL to a pem file publicly accessible on the internet</li>
     * </ul>
     * An empty string is ignored.
     */
    private final String privateKey;

    public JwtProperties(
        @DefaultValue("true") boolean bootstrap,
        @DefaultValue("") String publicKey,
        @DefaultValue("") String privateKey) {

        this.bootstrap = bootstrap;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public boolean isBootstrap() {
        return bootstrap;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }
}
