package me.forslund.tokensecurity.filters;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import me.forslund.tokensecurity.TokenSecurityKeyProvider;
import me.forslund.tokensecurity.TokenValidatorBuilder;
import me.forslund.tokensecurity.throwable.JwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static java.util.Objects.requireNonNull;

/**
 * Security filter that executes before the built-in Spring Security filters and that looks for a JWT token in the
 * Authorization-header. If found, it validates the token and sets the correct user in the security context if it was
 * valid. If it was invalid, then the filter chain stops with a 401 error. If the header is missing, then this filter
 * is ignored (leaving the security context empty).
 */
@Component
@Order(SecurityProperties.DEFAULT_FILTER_ORDER - 1)
public class AuthorizationHeaderFilter extends OncePerRequestFilter {

    private final static Logger LOGGER = LoggerFactory.getLogger(AuthorizationHeaderFilter.class);
    private final UserDetailsService userDetailsService;
    private final TokenSecurityKeyProvider tokenSecurityKeyProvider;

    private @Value("${jwt.issuer:localhost}") String expectedIssuer;
    private @Value("${jwt.audience:localhost}") String expectedAudience;
    private @Value("${jwt.scope}") String expectedScope;

    public AuthorizationHeaderFilter(UserDetailsService userDetailsService, TokenSecurityKeyProvider tokenSecurityKeyProvider) {
        this.userDetailsService       = requireNonNull(userDetailsService);
        this.tokenSecurityKeyProvider = requireNonNull(tokenSecurityKeyProvider);
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            authHeader = authHeader.substring(7);

            var validator = TokenValidatorBuilder.create(tokenSecurityKeyProvider)
                .withIssuer(expectedIssuer)
                .withAudience(expectedAudience)
                .withScope(expectedScope)
                .build();

            try {
                var claims = validator.parse(authHeader);
                var subject = claims.getSubject();

                final UserDetails userDetails;
                try {
                    userDetails = userDetailsService.loadUserByUsername(subject);
                } catch (final UsernameNotFoundException ex) {
                    LOGGER.error("JWT token is valid, but user could not be found in database.");
                    throw new JwtException(JwtException.Reason.USER_NOT_FOUND, ex);
                }

                Authentication authentication = new OneTimeTokenAuthenticationToken(userDetails, authHeader);
                SecurityContextHolder.getContext().setAuthentication(authentication);

            } catch (final JwtException ex) {
                reject(response, ex.getMessage());
                return;
            }
        }

        super.doFilter(request, response, filterChain);
    }

    private void reject(HttpServletResponse response, String msg) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"" + msg + "\"}");
    }
}
