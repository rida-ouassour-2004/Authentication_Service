package com.freelanceplatform.auth.DTO;
public record AuthResponse(
        String accessToken,
        String tokenType // Généralement "Bearer"
) {
    public AuthResponse(String accessToken) {
        this(accessToken, "Bearer");
    }
}

