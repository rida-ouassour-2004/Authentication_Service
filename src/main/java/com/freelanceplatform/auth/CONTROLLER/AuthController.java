package com.freelanceplatform.auth.CONTROLLER;
import com.freelanceplatform.auth.DTO.AuthResponse;
import com.freelanceplatform.auth.DTO.LoginRequest;
import com.freelanceplatform.auth.DTO.RegisterRequest;
import com.freelanceplatform.auth.SERVICE.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth") // Standard de versioning d'API
@RequiredArgsConstructor // Génère le constructeur pour l'injection
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(
            @Valid @RequestBody RegisterRequest request
    ) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request
    ) {
        return ResponseEntity.ok(authService.login(request));
    }
}
