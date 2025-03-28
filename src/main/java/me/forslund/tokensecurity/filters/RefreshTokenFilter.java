package me.forslund.tokensecurity.filters;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import me.forslund.tokensecurity.TokenSecurityKeyProvider;
import me.forslund.tokensecurity.TokenValidatorBuilder;
import me.forslund.tokensecurity.internal.JwtTokenService;
import me.forslund.tokensecurity.throwable.JwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Security filter that checks for POST requests to the /login/refresh endpoint. If the request matches, then it will
 * check if a valid refresh token exists in a secure cookie called 'jwt.token'. If it exists, then a new access token
 * will be issued with a 202 status and returned in the 'accessToken' field of the response body. If the cookie does not
 * exist or is invalid, then a 401 will be returned.
 */
@Component
@Order(SecurityProperties.DEFAULT_FILTER_ORDER - 1)
public class RefreshTokenFilter extends OncePerRequestFilter {

    private final static Logger LOGGER = LoggerFactory.getLogger(RefreshTokenFilter.class);

    private final UserDetailsService userDetailsService;
    private final TokenSecurityKeyProvider tokenSecurityKeyProvider;
    private final JwtTokenService jwtTokenService;

    private @Value("${jwt.refreshUrl:/login/refresh}") String refreshUrl;
    private @Value("${jwt.cookie.name:jwt.token}") String cookieName;
    private @Value("${jwt.issuer:localhost}") String expectedIssuer;
    private @Value("${jwt.audience:localhost}") String expectedAudience;

    public RefreshTokenFilter(UserDetailsService userDetailsService, TokenSecurityKeyProvider tokenSecurityKeyProvider, JwtTokenService jwtTokenService) {
        this.userDetailsService = userDetailsService;
        this.tokenSecurityKeyProvider = tokenSecurityKeyProvider;
        this.jwtTokenService = jwtTokenService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        if ("POST".equals(request.getMethod()) && refreshUrl.equals(request.getRequestURI())) {
            LOGGER.trace("Request POST {} matched.", refreshUrl);
            var cookieValue = extractRefreshTokenFromCookie(request);
            if (cookieValue.isEmpty()) {
                LOGGER.error("No refresh token found in cookie.");
                reject(response, "jwt.missing_cookie");
                return;
            }

            var validator = TokenValidatorBuilder.create(tokenSecurityKeyProvider)
                .withIssuer(expectedIssuer)
                .withAudience(expectedAudience)
                .withScope("refresh")
                .build();

            try {
                var claims = validator.parse(cookieValue.get());
                var subject = claims.getSubject();

                final UserDetails userDetails;
                try {
                    userDetails = userDetailsService.loadUserByUsername(subject);
                } catch (final UsernameNotFoundException ex) {
                    LOGGER.error("JWT token is valid, but user could not be found in database.");
                    throw new JwtException(JwtException.Reason.USER_NOT_FOUND, ex);
                }

                var signedJWT = jwtTokenService.createAccessToken(userDetails);
                var accessToken = signedJWT.serialize();
                setRefreshResponse(response, accessToken);
                return;

            } catch (final JwtException ex) {
                reject(response, ex.getMessage());
                return;
            }
        }

        super.doFilter(request, response, filterChain);
    }

    private Optional<String> extractRefreshTokenFromCookie(HttpServletRequest request) {
        return Optional.ofNullable(request.getCookies()).stream()
            .flatMap(Stream::of)
            .filter(cookie -> cookie.getName().equals(cookieName))
            .map(Cookie::getValue)
            .findAny();
    }

    private void setRefreshResponse(HttpServletResponse response, String accessToken) throws IOException {
        response.setStatus(HttpServletResponse.SC_ACCEPTED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"accessToken\":\"" + accessToken + "\"}");
    }

    private void reject(HttpServletResponse response, String msg) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"" + msg + "\"}");
    }
}
