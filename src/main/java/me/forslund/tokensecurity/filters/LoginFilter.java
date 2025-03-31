package me.forslund.tokensecurity.filters;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static java.util.Objects.requireNonNull;

@Component
@Order(SecurityProperties.DEFAULT_FILTER_ORDER - 1)
public class LoginFilter extends OncePerRequestFilter {

    private final static Logger LOGGER = LoggerFactory.getLogger(LoginFilter.class);

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final ObjectMapper objectMapper;
    private final JwtTokenService jwtTokenService;

    private @Value("${jwt.loginUrl:/login}") String loginUrl;
    private @Value("${jwt.cookie.name:jwt.token}") String cookieName;
    private @Value("${jwt.cookie.domain:localhost}") String cookieDomain;
    private @Value("${jwt.cookie.secure:false}") boolean secureCookie;
    private @Value("${server.servlet.context-path:/}") boolean pathPrefix;

    public LoginFilter(UserDetailsService userDetailsService,
                       @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection") PasswordEncoder passwordEncoder,
                       ObjectMapper objectMapper,
                       JwtTokenService jwtTokenService) {
        this.userDetailsService = requireNonNull(userDetailsService);
        this.passwordEncoder    = requireNonNull(passwordEncoder);
        this.objectMapper       = requireNonNull(objectMapper);
        this.jwtTokenService    = requireNonNull(jwtTokenService);
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        if ("POST".equals(request.getMethod()) && loginUrl.equals(request.getServletPath())) {
            LOGGER.trace("Request POST {} matched.", loginUrl);

            if (request.getContentType() == null || !request.getContentType().equals(MediaType.APPLICATION_JSON_VALUE)) {
                reject(response, "login.unsupportedContentType");
                return;
            }

            // Parse JSON data
            JsonNode json;
            try (var stream = request.getInputStream()) {
                json = objectMapper.readTree(stream);
            }

            if (!json.isObject()) {
                reject(response, "login.expectedLogin");
                return;
            }

            var username = json.get("username").textValue();
            var password = json.get("password").textValue();
            if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
                reject(response, "login.missingUsernameOrPassword");
                return;
            }

            // Find user in database
            final UserDetails userDetails;
            try {
                userDetails = userDetailsService.loadUserByUsername(username);
            } catch (final UsernameNotFoundException ex) {
                reject(response, "login.userNotFound");
                return;
            }

            // Make sure password matches
            if (!passwordEncoder.matches(password, userDetails.getPassword())) {
                reject(response, "login.userNotFound"); // Must be same error as above to prevent leaking info about users
                return;
            }

            // Create refresh token
            SignedJWT refreshToken;
            JWTClaimsSet refreshTokenClaims;
            try {
                refreshToken = jwtTokenService.createRefreshToken(userDetails);
                refreshTokenClaims = refreshToken.getJWTClaimsSet();
            } catch (final JwtException ex) {
                throw new RuntimeException("Failed to create JWT refresh token.", ex);
            } catch (final ParseException ex) {
                throw new RuntimeException("Failed to extract claims from generated JWT refresh token.", ex);
            }

            var validSeconds = (int) Instant.now().until(
                refreshTokenClaims.getExpirationTime().toInstant(),
                ChronoUnit.SECONDS);

            Cookie cookie = new Cookie(cookieName, refreshToken.serialize());
            cookie.setPath("/");
            cookie.setHttpOnly(true);
            cookie.setSecure(secureCookie);
            cookie.setMaxAge(validSeconds);
            cookie.setDomain(cookieDomain);
            response.addCookie(cookie);

            // Create access token
            try {
                var signedJwt = jwtTokenService.createAccessToken(userDetails);
                setLoginResponse(response, signedJwt.serialize());
                return;

            } catch (final JwtException ex) {
                throw new RuntimeException("Failed to create JWT access token.", ex);
            }
        }

        super.doFilter(request, response, filterChain);
    }

    private void setLoginResponse(HttpServletResponse response, String accessToken) throws IOException {
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
