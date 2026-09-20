package com.example.msauthkyc.controller;

import com.example.msauthkyc.model.AccessTokenResponse;
import com.example.msauthkyc.model.LoginResponse;
import com.example.msauthkyc.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @GetMapping("/me")
    public ResponseEntity<LoginResponse> login(@AuthenticationPrincipal OidcUser oidcUser, Authentication authentication) {
        return ResponseEntity.ok(authService.handleLogin(oidcUser, authentication));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AccessTokenResponse> refresh(
            @CookieValue(name = "refresh_token", required = false) String refreshToken) {
        return authService.refreshToken(refreshToken);
    }
}