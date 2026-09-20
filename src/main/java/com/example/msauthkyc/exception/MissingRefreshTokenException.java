package com.example.msauthkyc.exception;

import com.example.libexception.exception.UnauthorizedException;
import com.example.msauthkyc.exception.error.AuthErrorCode;

public class MissingRefreshTokenException extends UnauthorizedException {

    public MissingRefreshTokenException() {
        super(AuthErrorCode.MISSING_REFRESH_TOKEN);
    }
}