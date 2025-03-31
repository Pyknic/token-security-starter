package me.forslund.tokensecurity.internal;

import me.forslund.tokensecurity.TokenSecurityProperties;
import me.forslund.tokensecurity.TokenSecurityKeyProvider;
import me.forslund.tokensecurity.throwable.JwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;
import java.util.StringJoiner;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.joining;

public final class TokenSecurityKeyProviderImpl implements TokenSecurityKeyProvider {

    private final static Logger LOGGER = LoggerFactory.getLogger(TokenSecurityKeyProviderImpl.class);
    private final static Pattern REMOVE_PATTERN = Pattern.compile("^-+(?:BEGIN|END)\\s(?:PUBLIC|PRIVATE)\\sKEY-+$");
    private final TokenSecurityProperties props;
    private final AtomicReference<RSAPublicKey> publicKey;
    private final AtomicReference<RSAPrivateKey> privateKey;

    public TokenSecurityKeyProviderImpl(TokenSecurityProperties props) {
        this.props = requireNonNull(props);
        this.publicKey   = new AtomicReference<>(null);
        this.privateKey  = new AtomicReference<>(null);
    }

    @Override
    public void saveKeyPairToDisk() {
        var publicKeyString = props.getPublicKey();
        var privateKeyString = props.getPrivateKey();

        if (!StringUtils.hasText(publicKeyString) ||
            !StringUtils.hasText(privateKeyString)) {

            throw new RuntimeException("Missing jwt.publicKey or jwt.privateKey property (required if jwt.bootstrap = true)");
        }

        var publicKeyPath = Path.of(publicKeyString);
        var privateKeyPath = Path.of(privateKeyString);

        final KeyPair keyPair;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048); // or 4096
            keyPair = keyGen.generateKeyPair();
        } catch (final NoSuchAlgorithmException ex) {
            throw new RuntimeException("Failed to generate RSA key pair", ex);
        }

        // Serialize to JSON
        String privateKeyPEM = encodeToPEM("PRIVATE KEY", keyPair.getPrivate().getEncoded());
        String publicKeyPEM = encodeToPEM("PUBLIC KEY", keyPair.getPublic().getEncoded());
        
        if (!Files.exists(publicKeyPath)) {
            try {
                Files.writeString(publicKeyPath, publicKeyPEM);
            } catch (final IOException ex) {
                throw new RuntimeException("Could not write public JWT RSA key to %s".formatted(publicKeyPath), ex);
            }
        }

        if (!Files.exists(privateKeyPath)) {
            try {
                Files.writeString(privateKeyPath, privateKeyPEM);
            } catch (final IOException ex) {
                throw new RuntimeException("Could not write private JWT RSA key to %s".formatted(privateKeyPath), ex);
            }
        }
    }

    @Override
    public Optional<RSAPublicKey> getPublicKey() {
        return lazyLoad(publicKey, () -> {
            var publicKeyString = props.getPublicKey();
            return loadKeySpec(publicKeyString, true)
                .map(keySpec -> {
                    try {
                        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
                        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
                    } catch (final NoSuchAlgorithmException ex) {
                        throw new RuntimeException("Expected RSA algorithm to be present, but it wasn't.", ex);
                    } catch (final InvalidKeySpecException ex) {
                        throw new RuntimeException("Key spec loaded from path '%s' was invalid.".formatted(publicKeyString), ex);
                    }
                });
        });
    }

    @Override
    public Optional<RSAPrivateKey> getPrivateKey() {
        return lazyLoad(privateKey, () -> {
            var privateKeyString = props.getPrivateKey();
            return loadKeySpec(privateKeyString, false)
                .map(keySpec -> {
                    try {
                        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
                        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
                    } catch (final NoSuchAlgorithmException ex) {
                        throw new RuntimeException("Expected RSA algorithm to be present, but it wasn't.", ex);
                    } catch (final InvalidKeySpecException ex) {
                        throw new RuntimeException("Key spec loaded from path '%s' was invalid.".formatted(privateKeyString), ex);
                    }
                });
        });
    }

    private static <T> Optional<T> lazyLoad(AtomicReference<T> storedValue, Supplier<Optional<T>> supplier) {
        var value = storedValue.get();
        if (value == null) {
            synchronized (TokenSecurityKeyProviderImpl.class) {
                value = storedValue.get();
                if (value == null) {
                    Optional<T> result = supplier.get();
                    result.ifPresent(storedValue::set);
                    return result;
                }
            }
        }
        return Optional.of(value);
    }

    private Optional<KeySpec> loadKeySpec(String keyString, boolean isPublicKey) {
        // Don't try to parse it as a path or URL if it is empty.
        if (!StringUtils.hasText(keyString)) return Optional.empty();

        return tryGetPath(keyString)
            .map(this::loadFileContents)
            .filter(StringUtils::hasText)
            .or(() -> Optional.of(keyString)
                .map(TokenSecurityKeyProviderImpl::stringToUrl)
                .map(this::loadRemoteContents)
                .filter(StringUtils::hasText)
            )
            .or(() -> Optional.of(processLines(keyString.lines()))
                .filter(StringUtils::hasText)
            )
            .map(str -> {
                try {
                    return Base64.getDecoder().decode(str);
                } catch (final IllegalArgumentException ex) {
                    throw new RuntimeException("Failed to decode base64-string: " + str, ex);
                }
            })
            .map(data -> isPublicKey
                ? new X509EncodedKeySpec(data)
                : new PKCS8EncodedKeySpec(data));
    }

    private Optional<Path> tryGetPath(final String string) {
        Path publicKeyPath;
        try {
            publicKeyPath = Paths.get(string);
        } catch (final InvalidPathException ex) {
            return Optional.empty();
        }

        if (Files.exists(publicKeyPath) &&
            Files.isRegularFile(publicKeyPath) &&
            Files.isReadable(publicKeyPath)) {
            return Optional.of(publicKeyPath);
        }

        return Optional.empty();
    }

    private String loadFileContents(final Path path) {
        try {
            try (var lineStream = Files.lines(path)) {
                return processLines(lineStream);
            }
        } catch (final IOException ex) {
            throw new RuntimeException("Failed to load JWT key at path: %s".formatted(path), ex);
        }
    }

    private String loadRemoteContents(final URL url) {
        LOGGER.trace("Try to load JWT key from URL: '{}'", url);
        try (var in = url.openStream()) {
            try (var reader = new BufferedReader(new InputStreamReader(in))) {
                try (var lineStream = reader.lines()) {
                    return processLines(lineStream);
                }
            }
        } catch (final IOException ex) {
            LOGGER.error("Failed to load JWT key from remote URL: '{}'", url, ex);
            throw new RuntimeException(ex);
        } finally {
            LOGGER.trace("Finished loading JWT key from URL: '{}'", url);
        }
    }

    private static String processLines(final Stream<String> stream) {
        return stream
            .map(String::trim)
            .filter(s -> !REMOVE_PATTERN.matcher(s).matches())
            .filter(StringUtils::hasText)
            .collect(joining());
    }

    private static URL stringToUrl(final String string) {
        try {
            return new URL(string);
        } catch (final MalformedURLException ex) {
            return null;
        }
    }

    private static String encodeToPEM(String title, byte[] keyBytes) {
        String delimiter = "\r\n";
        String encoded = Base64
            .getMimeEncoder(64, delimiter.getBytes(StandardCharsets.US_ASCII))
            .encodeToString(keyBytes);

        var dashes = "-".repeat(5);
        var joiner = new StringJoiner(delimiter);
        joiner.add(dashes + "BEGIN " + title + dashes);
        joiner.add(encoded);
        joiner.add(dashes + "END " + title + dashes);
        joiner.add("");
        return joiner.toString();
    }
}
