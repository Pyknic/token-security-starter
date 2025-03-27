
package me.forslund.tokensecurity.filters;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Order(SecurityProperties.DEFAULT_FILTER_ORDER - 1)
public class LogoutFilter extends OncePerRequestFilter {

    private final static Logger LOGGER = LoggerFactory.getLogger(LogoutFilter.class);

    private @Value("${jwt.logoutUrl:/logout}") String logoutUrl;
    private @Value("${jwt.cookie.name:jwt.token}") String cookieName;
    private @Value("${jwt.cookie.domain:localhost}") String cookieDomain;
    private @Value("${jwt.cookie.secure:false}") boolean secureCookie;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        if ("POST".equals(request.getMethod()) && logoutUrl.equals(request.getRequestURI())) {
            LOGGER.trace("Request POST {} matched.", logoutUrl);

            // Clear cookie
            Cookie cookie = new Cookie(cookieName, null);
            cookie.setPath("/");
            cookie.setHttpOnly(true);
            cookie.setSecure(secureCookie);
            cookie.setMaxAge(0);
            cookie.setDomain(cookieDomain);
            response.addCookie(cookie);

            // Respond to the user
            setLogoutResponse(response);
            return;
        }

        super.doFilter(request, response, filterChain);
    }

    private void setLogoutResponse(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }
}
