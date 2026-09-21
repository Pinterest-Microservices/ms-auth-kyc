package com.example.msauthkyc.exception;

import com.example.libexception.exception.BadRequestException;
import com.example.msauthkyc.exception.error.AuthErrorCode;

public class InvalidRefreshTokenException extends BadRequestException {

    public InvalidRefreshTokenException() {
        super(AuthErrorCode.INVALID_REFRESH_TOKEN);
    }
}