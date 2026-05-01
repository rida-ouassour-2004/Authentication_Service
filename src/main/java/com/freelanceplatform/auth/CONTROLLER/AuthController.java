package com.freelanceplatform.auth.CONTROLLER;
import com.freelanceplatform.auth.DTO.AuthResponse;
import com.freelanceplatform.auth.DTO.LoginRequest;
import com.freelanceplatform.auth.DTO.RegisterRequest;
import com.freelanceplatform.auth.ENTITY.User;
import com.freelanceplatform.auth.REPOSITORY.UserRepository;
import com.freelanceplatform.auth.SERVICE.AuthService;
import com.freelanceplatform.auth.SERVICE.JwtService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth") // Standard de versioning d'API
@RequiredArgsConstructor // Génère le constructeur pour l'injection
public class AuthController {

    private final AuthService authService;
    private final UserRepository userRepository;
    private final JwtService jwtService;

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
    @GetMapping("/verify")
    public ResponseEntity<String> verifyUser(@RequestParam("token") String token) {
        try {
            // 1. Extraire l'email (valide aussi la signature et l'expiration via extractEmail)
            String email = jwtService.extractEmail(token);

            // 2. Chercher l'utilisateur proprement
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));

            // 3. Vérifier si déjà vérifié (optionnel, pour éviter des sauvegardes inutiles)
            if (user.isVerified()) {
                return ResponseEntity.ok("Votre compte est déjà activé.");
            }

            // 4. Activer et sauvegarder
            user.setVerified(true);
            userRepository.save(user);

            return ResponseEntity.ok("Compte vérifié avec succès ! Vous pouvez maintenant vous connecter.");

        } catch (Exception e) {
            // Capture les erreurs de token expiré ou invalide
            return ResponseEntity.status(400).body("Lien de vérification invalide ou expiré.");
        }
    }


}
