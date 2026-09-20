package com.example.msauthkyc.service;

import com.example.msauthkyc.exception.InvalidRefreshTokenException;
import com.example.msauthkyc.model.AccessTokenResponse;
import com.example.msauthkyc.model.KeycloakTokenResponse;
import com.example.msauthkyc.model.LoginResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;

import static com.example.msauthkyc.util.TokenUtil.validateRefreshToken;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final String REGISTRATION_ID = "pin-client";
    private static final String REFRESH_TOKEN = "refresh_token";
    private static final String TOKEN_ENDPOINT_PATH = "/protocol/openid-connect/token";

    private final OAuth2AuthorizedClientService authorizedClientService;
    private final RestTemplate restTemplate;

    @Value("${spring.security.oauth2.client.registration.pin-client.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.pin-client.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.provider.keycloak.issuer-uri}")
    private String issuerUri;

    public LoginResponse handleLogin(OidcUser oidcUser, Authentication authentication) {
        OAuth2AuthorizedClient authorizedClient = loadAuthorizedClient(authentication);

        String accessToken = authorizedClient.getAccessToken().getTokenValue();
        String pictureUrl = oidcUser.getPicture();

        return LoginResponse.builder()
                .accountId(oidcUser.getSubject())
                .email(oidcUser.getEmail())
                .fullName(oidcUser.getFullName())
                .pictureUrl(pictureUrl)
                .accessToken(accessToken)
                .build();
    }

    public ResponseEntity<AccessTokenResponse> refreshToken(String refreshToken) {
        validateRefreshToken(refreshToken);

        MultiValueMap<String, String> form = buildRefreshForm(refreshToken);
        HttpEntity<MultiValueMap<String, String>> requestEntity = buildRequestEntity(form);

        try {
            KeycloakTokenResponse keycloakResponse = restTemplate.postForObject(
                    tokenEndpoint(),
                    requestEntity,
                    KeycloakTokenResponse.class
            );

            if (keycloakResponse == null) {
                throw new InvalidRefreshTokenException();
            }

            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, getResponseCookie(keycloakResponse.getRefreshToken()).toString())
                    .body(AccessTokenResponse.builder()
                            .accessToken(keycloakResponse.getAccessToken())
                            .build());

        } catch (HttpClientErrorException.BadRequest | HttpClientErrorException.Unauthorized e) {
            throw new InvalidRefreshTokenException();
        }
    }

    private OAuth2AuthorizedClient loadAuthorizedClient(Authentication authentication) {
        return authorizedClientService.loadAuthorizedClient(REGISTRATION_ID, authentication.getName());
    } // cari istifadecini getiriri //todo: arasdirma et

    private String extractRefreshToken(OAuth2AuthorizedClient authorizedClient) {
        return authorizedClient.getRefreshToken() != null
                ? authorizedClient.getRefreshToken().getTokenValue()
                : null;
    }

    private MultiValueMap<String, String> buildRefreshForm(String refreshToken) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", REFRESH_TOKEN);
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        form.add("refresh_token", refreshToken);
        return form;
    }

    private HttpEntity<MultiValueMap<String, String>> buildRequestEntity(MultiValueMap<String, String> form) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        return new HttpEntity<>(form, headers);
    }

    private String tokenEndpoint() {
        return issuerUri + TOKEN_ENDPOINT_PATH;
    }

    private ResponseCookie getResponseCookie(String refreshToken) {
        return ResponseCookie.from("refresh_token", refreshToken)
                .httpOnly(true)
                .secure(false)
                .path("/")
                .maxAge(Duration.ofDays(30))
                .sameSite("None")
                .build();
    }
}