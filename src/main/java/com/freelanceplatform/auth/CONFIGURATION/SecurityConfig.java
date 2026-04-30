package com.freelanceplatform.auth.CONFIGURATION;

import com.freelanceplatform.auth.SECURITY.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 1. Désactiver le CSRF (inutile en mode stateless/JWT)
                .csrf(csrf -> csrf.disable())

                // 2. Définir les droits d'accès aux routes
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/v1/auth/**").permitAll() // Routes publiques (login/register)
                        .anyRequest().authenticated()                  // Tout le reste est protégé
                )

                // 3. Gestion de session Stateless (pas de session HTTP côté serveur)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // 4. Configurer le provider d'authentification
                .authenticationProvider(authenticationProvider)

                // 5. Ajouter notre filtre JWT avant le filtre de login classique
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
