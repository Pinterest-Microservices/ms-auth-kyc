package com.example.msauthkyc.config;

import com.example.msauthkyc.exception.MissingOauth2RefreshTokenException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.NonNull;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Configuration
public class SecurityConfig {

    private static final String AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/authorization";
    private static final String REGISTRATION_ID = "pin-client";

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   ClientRegistrationRepository clientRegistrationRepository, OAuth2AuthorizedClientService authorizedClientService)
            throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/**").permitAll()
                        .requestMatchers("/refresh/**").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(endpoint -> endpoint
                                .authorizationRequestResolver(
                                        authorizationRequestResolver(clientRegistrationRepository)
                                )
                        )
                        .successHandler(oauth2CookieSuccessHandler(authorizedClientService))
                )
                .logout(logout -> logout
                        .logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrationRepository))
                );

        return http.build();
    }

    private OAuth2AuthorizationRequestResolver authorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository) {

        DefaultOAuth2AuthorizationRequestResolver defaultResolver =
                new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository, AUTHORIZATION_REQUEST_BASE_URI);

        return new OAuth2AuthorizationRequestResolver() {

            @Override
            public OAuth2AuthorizationRequest resolve(@NonNull HttpServletRequest request) {
                OAuth2AuthorizationRequest authRequest = defaultResolver.resolve(request);
                return customizeAuthorizationRequest(authRequest);
            }

            @Override
            public OAuth2AuthorizationRequest resolve(@NonNull HttpServletRequest request,
                                                      @NonNull String clientRegistrationId) {
                OAuth2AuthorizationRequest authRequest =
                        defaultResolver.resolve(request, clientRegistrationId);
                return customizeAuthorizationRequest(authRequest);
            }

            private OAuth2AuthorizationRequest customizeAuthorizationRequest(
                    OAuth2AuthorizationRequest authRequest) {
                if (authRequest == null) {
                    return null;
                }
                Map<String, Object> extraParams = new HashMap<>(authRequest.getAdditionalParameters());
                extraParams.put("kc_idp_hint", "google");

                return OAuth2AuthorizationRequest.from(authRequest)
                        .additionalParameters(extraParams)
                        .build();
            }
        };
    }

    private AuthenticationSuccessHandler oauth2CookieSuccessHandler(
            OAuth2AuthorizedClientService authorizedClientService) {

        return (request, response, authentication) -> {
            OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                    REGISTRATION_ID, authentication.getName());

            if (Objects.isNull(client)
                    || Objects.isNull(client.getRefreshToken()))
                throw new MissingOauth2RefreshTokenException();
            // todo: bug sink report olunmalidi

            ResponseCookie refreshCookie =
                    ResponseCookie.from("refresh_token", client.getRefreshToken().getTokenValue())
                            .httpOnly(true)
                            .secure(false) // http
                            .path("/")
                            .maxAge(Duration.ofDays(30))
                            .sameSite("Lax") // http
                            .build();

            response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());

            // todo redirect yazilsin
        };
    }

    private LogoutSuccessHandler oidcLogoutSuccessHandler(ClientRegistrationRepository repo) {
        OidcClientInitiatedLogoutSuccessHandler handler =
                new OidcClientInitiatedLogoutSuccessHandler(repo);
        handler.setPostLogoutRedirectUri("https://pinterest.com"); // todo: delete
        return handler;
    }

}