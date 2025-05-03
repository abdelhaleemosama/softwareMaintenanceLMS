    package net.java.lms_backend.Security.Jwt;

    import io.jsonwebtoken.Claims;
    import jakarta.servlet.FilterChain;
    import jakarta.servlet.http.HttpServletRequest;
    import jakarta.servlet.http.HttpServletResponse;
    import org.springframework.security.authentication.AuthenticationManager;
    import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
    import org.springframework.security.core.context.SecurityContextHolder;
    import org.springframework.web.filter.OncePerRequestFilter;
    import jakarta.servlet.ServletException;
    import java.io.IOException;
    import org.springframework.security.core.authority.SimpleGrantedAuthority;

    import java.util.ArrayList;
    import java.util.List;

    public class JwtAuthenticationFilter extends OncePerRequestFilter {

        private AuthenticationManager authenticationManager;
        private JwtUtil jwtUtil;

        public JwtAuthenticationFilter(AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
            this.authenticationManager = authenticationManager;
            this.jwtUtil = jwtUtil;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
            String token = request.getHeader("Authorization");
            if (token != null && token.startsWith("Bearer ")) {
                token = token.substring(7);
                String username = jwtUtil.extractUsername(token);
                if (username != null && !jwtUtil.isTokenExpired(token)) {
                    // Set authentication in SecurityContext
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, null, new ArrayList<>());
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
            filterChain.doFilter(request, response);
        }
    }

