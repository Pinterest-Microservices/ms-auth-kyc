package com.example.msauthkyc.exception.error;

import com.example.libexception.error.ErrorCode;
import org.springframework.http.HttpStatus;

public enum AuthErrorCode implements ErrorCode {

    INVALID_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "Refresh token is invalid or expired."),
    MISSING_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "Refresh token is required."),
    MISSING_OAUTH_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "Refresh token is not provided");

    private final HttpStatus httpStatus;
    private final String defaultMessage;

    AuthErrorCode(HttpStatus httpStatus, String defaultMessage) {
        this.httpStatus = httpStatus;
        this.defaultMessage = defaultMessage;
    }

    @Override
    public String getCode() {
        return name();
    }

    @Override
    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    @Override
    public String getDefaultMessage() {
        return defaultMessage;
    }
}