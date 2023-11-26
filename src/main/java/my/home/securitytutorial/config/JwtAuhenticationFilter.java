package my.home.securitytutorial.config;

import java.io.IOException;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.experimental.NonFinal;
import my.home.securitytutorial.service.JwtService;

@Component
@RequiredArgsConstructor
public class JwtAuhenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(@NonFinal HttpServletRequest request, @NonFinal HttpServletResponse response,
            @NonFinal FilterChain filterChain)
            throws ServletException, IOException {
        final String authorizationHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            userEmail = jwtService.extractUsername(jwt);
        } else {
            throw new RuntimeException("JWT is missing");
        }
    }

}
