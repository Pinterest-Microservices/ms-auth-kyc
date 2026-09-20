package com.example.msauthkyc.exception;

import com.example.libexception.exception.UnauthorizedException;
import com.example.msauthkyc.exception.error.AuthErrorCode;

public class MissingOauth2RefreshTokenException extends UnauthorizedException {

    public MissingOauth2RefreshTokenException() {
        super(AuthErrorCode.MISSING_OAUTH_REFRESH_TOKEN);
    }
}
