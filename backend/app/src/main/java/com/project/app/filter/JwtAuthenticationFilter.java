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
import org.springframework.http.HttpStatus;
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

        try {
            if(authHeader != null){
                username = jwtService.getUsernameFromToken(authHeader);
                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
                    if (jwtService.validateToken(authHeader, userDetails) ) {
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
            }

        } catch (IllegalArgumentException e) {
            System.out.println("an error occured during getting username from token"+ e);
        } catch (ExpiredJwtException e) {
            System.out.println("the token is expired and not valid anymore"+ e);
            response.sendError(HttpServletResponse.SC_FORBIDDEN,
                    "the token is expired and not valid anymore");
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        } catch (SignatureException e) {
            System.out.println("Authentication Failed. Username or Password not valid.");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                    "Authentication Failed. Username or Password not valid.");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        } catch (MalformedJwtException exception) {
            System.out.println("Request to parse invalid JWT : failed : {}"+ exception.getMessage());
            response.sendError(HttpServletResponse.SC_FORBIDDEN,
                    "Request to parse invalid JWT");
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);

        }catch (Exception exception) {
            System.out.println("Exception : {}"+ exception.getMessage());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Exception");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }


        filterChain.doFilter(request, response);
    }
}