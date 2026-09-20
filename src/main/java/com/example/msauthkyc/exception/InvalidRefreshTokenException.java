package com.example.msauthkyc.exception;

import com.example.libexception.exception.UnauthorizedException;
import com.example.msauthkyc.exception.error.AuthErrorCode;

public class InvalidRefreshTokenException extends UnauthorizedException {

    public InvalidRefreshTokenException() {
        super(AuthErrorCode.INVALID_REFRESH_TOKEN);
    }
}