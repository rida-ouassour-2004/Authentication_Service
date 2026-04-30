package com.freelanceplatform.auth.DTO;
import com.freelanceplatform.auth.ENTITY.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.Set;

public record RegisterRequest(
        @NotBlank @Email String email,
        @NotBlank @Size(min = 6) String password,
        Set<Role> roles // Ou un rôle par défaut si vide
) {}


