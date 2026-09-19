package com.example.msauthkyc.controller;

import com.example.msauthkyc.model.LoginResponse;
import com.example.msauthkyc.model.RefreshTokenRequest;
import com.example.msauthkyc.model.TokenResponse;
import com.example.msauthkyc.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @GetMapping("/me")
    public LoginResponse login(@AuthenticationPrincipal OidcUser oidcUser, Authentication authentication) {
        return authService.handleLogin(oidcUser, authentication);
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(@RequestBody RefreshTokenRequest request) {
        return authService.refreshToken(request.getRefreshToken());
    }
}