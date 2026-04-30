package com.freelanceplatform.auth.SERVICE;

import com.freelanceplatform.auth.DTO.AuthResponse;
import com.freelanceplatform.auth.DTO.LoginRequest;
import com.freelanceplatform.auth.DTO.RegisterRequest;
import com.freelanceplatform.auth.ENTITY.Role;
import com.freelanceplatform.auth.ENTITY.User;
import com.freelanceplatform.auth.REPOSITORY.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthResponse register(RegisterRequest request) {
        // 1. Vérification
        if(userRepository.existsByEmail(request.email())) {
            throw new RuntimeException("Cet email est déjà utilisé");
        }

        // 2. Création de l'entité
        User user = new User();
        user.setEmail(request.email());
        // Hashage du mot de passe avec BCrypt
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setRoles(request.roles() == null ? Set.of(Role.USER) : request.roles());

        // 3. Sauvegarde
        userRepository.save(user);

        // 4. Génération du token
        String token = jwtService.generateToken(user);
        return new AuthResponse(token);
    }

    public AuthResponse login(LoginRequest request) {
        // 1. On demande à Spring Security de vérifier le couple Email/Password
        // Si c'est incorrect (mauvais mot de passe ou email), il lance une exception automatiquement
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.email(),
                        request.password()
                )
        );

        // 2. Si on arrive ici, c'est que l'utilisateur est authentifié !
        // On le récupère depuis la base de données
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé après authentification"));

        // 3. On génère le token avec ses informations
        String token = jwtService.generateToken(user);

        // 4. On renvoie la réponse au client
        return new AuthResponse(token);
    }

}

