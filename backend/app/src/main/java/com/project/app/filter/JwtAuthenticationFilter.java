package com.project.app.filter;

import com.project.app.auth.service.JwtService;
import com.project.app.user.service.ControlService;
import com.project.app.util.HeaderConstant;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final ControlService controlService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException, AuthenticationException {

        final String authHeader = request.getHeader(HeaderConstant.AUTHORIZATION);
        final String jwt;
        final String username;

        jwt = authHeader.substring(7);
        try {
            username = jwtService.extractUsername(jwt);
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
                if (jwtService.isTokenValid(jwt, userDetails) ) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    authToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (IllegalArgumentException e) {
            System.out.println("an error occured during getting username from token"+ e);
        } catch (ExpiredJwtException e) {
            System.out.println("the token is expired and not valid anymore"+ e);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                    "the token is expired and not valid anymore");
        } catch (SignatureException e) {
            System.out.println("Authentication Failed. Username or Password not valid.");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                    "Authentication Failed. Username or Password not valid.");

        } catch (MalformedJwtException exception) {
            System.out.println("Request to parse invalid JWT : failed : {}"+ exception.getMessage());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                    "Request to parse invalid JWT");

        }catch (Exception exception) {
            System.out.println("Exception : {}"+ exception.getMessage());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Exception");
        }


        filterChain.doFilter(request, response);
    }
}