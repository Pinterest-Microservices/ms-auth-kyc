package com.example.msauthkyc.controller;

import com.example.msauthkyc.model.AccessTokenResponse;
import com.example.msauthkyc.model.KeycloakTokenResponse;
import com.example.msauthkyc.model.LoginResponse;
import com.example.msauthkyc.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private static final String REFRESH_TOKEN_COOKIE_NAME = "refresh_token";

    private final AuthService authService;

    @GetMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @AuthenticationPrincipal OidcUser oidcUser,
            Authentication authentication
    ) {
        return ResponseEntity.ok(authService.handleLogin(oidcUser, authentication));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@AuthenticationPrincipal Jwt jwt) {

        authService.logout(jwt.getSubject());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, buildExpiredCookie().toString())
                .build();
    }

    @PostMapping("/refresh")
    public ResponseEntity<AccessTokenResponse> refresh(
            @CookieValue(name = REFRESH_TOKEN_COOKIE_NAME, required = false) String refreshToken
    ) {
        KeycloakTokenResponse tokenResponse = authService.refreshToken(refreshToken);

        ResponseCookie cookie = buildRefreshTokenCookie(tokenResponse.getRefreshToken());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(AccessTokenResponse.builder()
                        .accessToken(tokenResponse.getAccessToken())
                        .build());
    }

    private ResponseCookie buildRefreshTokenCookie(String refreshToken) {
        return ResponseCookie.from(REFRESH_TOKEN_COOKIE_NAME, refreshToken)
                .httpOnly(true)
                .secure(false) // todo https
                .path("/")
                .maxAge(Duration.ofDays(30))
                .sameSite("Lax")
                .build();
    }

    private ResponseCookie buildExpiredCookie() {
        return ResponseCookie.from(REFRESH_TOKEN_COOKIE_NAME, "")
                .httpOnly(true)
                .secure(false)
                .path("/")
                .maxAge(0)
                .sameSite("Lax")
                .build();
    }
}