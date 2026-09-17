package com.example.msauthkyc.exception;

import com.example.libexception.exception.UnauthorizedException;
import com.example.msauthkyc.error.AuthErrorCode;

public class InvalidRefreshTokenException extends UnauthorizedException {

    public InvalidRefreshTokenException() {
        super(AuthErrorCode.INVALID_REFRESH_TOKEN);
    }

    public InvalidRefreshTokenException(String message) {
        super(AuthErrorCode.INVALID_REFRESH_TOKEN, message);
    }
}