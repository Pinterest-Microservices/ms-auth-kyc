package com.example.msauthkyc.util;

import com.example.msauthkyc.exception.MissingRefreshTokenException;

public class TokenUtil {

    private TokenUtil() {
    }

    public static void validateRefreshToken(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new MissingRefreshTokenException();
        }
    }
}