package com.example.msauthkyc.service;

import com.example.libauthkyc.autoconfigure.LibAuthKycProperties;
import com.example.libexception.error.CommonErrorCode;
import com.example.libexception.exception.UnauthorizedException;
import com.example.msauthkyc.exception.InvalidRefreshTokenException;
import com.example.msauthkyc.model.KeycloakTokenResponse;
import com.example.msauthkyc.model.LoginResponse;
import lombok.RequiredArgsConstructor;
import org.keycloak.admin.client.Keycloak;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import static com.example.msauthkyc.util.OAuth2ConstantsUtil.*;
import static com.example.msauthkyc.util.TokenUtil.validateRefreshToken;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final OAuth2AuthorizedClientService authorizedClientService;
    private final RestTemplate restTemplate;
    private final Keycloak keycloak;
    private final LibAuthKycProperties libAuthKycProperties;

    @Value("${spring.security.oauth2.client.registration.pin-client.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.pin-client.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.provider.keycloak.issuer-uri}")
    private String issuerUri;

    public LoginResponse handleLogin(OidcUser oidcUser, Authentication authentication) {
        OAuth2AuthorizedClient authorizedClient = loadAuthorizedClient(authentication);
        if (authorizedClient == null) {
            throw new UnauthorizedException(CommonErrorCode.UNAUTHORIZED);
        }

        return LoginResponse.builder()
                .accountId(oidcUser.getSubject())
                .email(oidcUser.getEmail())
                .fullName(oidcUser.getFullName())
                .pictureUrl(oidcUser.getPicture())
                .accessToken(authorizedClient.getAccessToken().getTokenValue())
                .build();
    }

    public void logout(String userId) {
        String realm = libAuthKycProperties.getKeycloak().getRealm();

        keycloak.realm(realm)
                .users()
                .get(userId)
                .logout();
    }

    public KeycloakTokenResponse refreshToken(String refreshToken) {
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

            return keycloakResponse;
        } catch (HttpClientErrorException.BadRequest | HttpClientErrorException.Unauthorized e) {
            throw new InvalidRefreshTokenException();
        }
    }

    private OAuth2AuthorizedClient loadAuthorizedClient(Authentication authentication) {
        return authorizedClientService.loadAuthorizedClient(REGISTRATION_ID, authentication.getName());
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
}