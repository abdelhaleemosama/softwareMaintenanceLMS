package net.java.lms_backend.controller;

import net.java.lms_backend.Security.Jwt.JwtUtil;
import net.java.lms_backend.Service.AuthService;
import net.java.lms_backend.dto.LoginRequestDTO;
import net.java.lms_backend.dto.RegisterDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import static net.java.lms_backend.mapper.UserMapper.ToUserLogin;

@RestController
@RequestMapping(path = "api/auth")
public class AuthController {

    private final AuthService authService;
//    private final AuthenticationManager authenticationManager;
//    private final JwtUtil jwtUtil;

    public AuthController(AuthService authService) {
        this.authService = authService;
//        this.authenticationManager = authenticationManager;
//        this.jwtUtil = jwtUtil;
    }

    @PostMapping("login")
    public ResponseEntity<String> Login(@RequestBody LoginRequestDTO loginRequest) {

       /* Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = jwtUtil.generateToken(loginRequest.getUsername());
        return ResponseEntity.ok(token);*/
        return authService.Login( ToUserLogin(loginRequest));
    }

    @PostMapping("register")
    public ResponseEntity<String> Register(@RequestBody RegisterDTO user) {
        return authService.register(user);
    }

    @GetMapping(path = "confirm")
    public ResponseEntity<String> confirm(@RequestParam("token") String token) {
        return authService.confirmToken(token);
    }
}
