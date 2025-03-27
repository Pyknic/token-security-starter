package me.forslund.tokensecurity.throwable;

import static java.util.Objects.requireNonNull;

public final class JwtException extends Exception {

    public enum Reason {
        INVALID_TOKEN,
        BAD_ALGORITH,
        INVALID_SIGNATURE,
        INTERNAL_ERROR,
        INVALID_CLAIMS,
        EXPIRED_TOKEN,
        TOKEN_NOT_YET_VALID,
        INVALID_ISSUER,
        INVALID_AUDIENCE,
        INVALID_SCOPE,
        INVALID_SUBJECT,
        USER_NOT_FOUND,
    }

    private final Reason reason;

    public JwtException(Reason reason) {
        this(reason, null);
    }

    public JwtException(Reason reason, Throwable cause) {
        super("jwt." + toCamelCase(reason.name()), cause);
        this.reason = requireNonNull(reason);
    }

    public Reason getReason() {
        return reason;
    }

    private static String toCamelCase(String snakeCase) {
        if (snakeCase == null || snakeCase.isEmpty()) {
            return snakeCase;
        }

        String[] words = snakeCase.split("_");
        StringBuilder camelCaseString = new StringBuilder(words[0].toLowerCase());

        for (int i = 1; i < words.length; i++) {
            camelCaseString
                .append(words[i].substring(0, 1).toUpperCase())
                .append(words[i].substring(1).toLowerCase());
        }

        return camelCaseString.toString();
    }
}
