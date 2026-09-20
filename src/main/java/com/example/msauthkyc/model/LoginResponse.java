package com.example.msauthkyc.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginResponse {

    private String accountId;
    private String email;
    private String fullName;
    private String pictureUrl;
    private String accessToken;
}