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
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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
    private final EmailService emailService; // Ajout requis ici

    public AuthResponse register(RegisterRequest request) {
        if(userRepository.existsByEmail(request.email())) {
            throw new RuntimeException("Cet email est déjà utilisé");
        }

        User user = new User();
        user.setEmail(request.email());
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setRoles(request.roles() == null ? Set.of(Role.USER) : request.roles());
        user.setVerified(false);

        userRepository.save(user);

        try {
            String verificationToken = jwtService.generateVerificationToken(user);
            emailService.sendVerificationEmail(user, verificationToken);
            System.out.println("DEBUG: Email envoyé avec succès");
        } catch (Exception e) {
            System.err.println("DEBUG ERROR: L'envoi du mail a échoué : " + e.getMessage());
            e.printStackTrace();
            return new AuthResponse("Utilisateur créé, mais l'envoi du mail a échoué. Contactez le support.");
        }

        return new AuthResponse("Inscription réussie ! Vérifiez vos mails.");
    }



    public AuthResponse login(LoginRequest request) {
        // 1. Authentification
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.email(),
                        request.password()
                )
        );

        // 2. Récupération
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new UsernameNotFoundException("Utilisateur non trouvé"));

        // 3. Vérification de sécurité
        if (!user.isVerified()) {
            throw new RuntimeException("Veuillez vérifier votre compte par email.");
        }

        // 4. Génération du Token
        String jwtToken = jwtService.generateToken(user);

        return new AuthResponse(jwtToken);
    }



}



