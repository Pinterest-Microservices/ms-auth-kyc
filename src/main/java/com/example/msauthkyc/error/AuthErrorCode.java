package com.example.msauthkyc.error;

import com.example.exceptionlib.error.ErrorCode;
import org.springframework.http.HttpStatus;

public enum AuthErrorCode implements ErrorCode {

    INVALID_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "Refresh token is invalid or expired."),
    INVALID_CREDENTIALS(HttpStatus.UNAUTHORIZED, "Invalid username or password."),
    USER_NOT_FOUND(HttpStatus.NOT_FOUND, "User could not be found."),
    USER_ALREADY_EXISTS(HttpStatus.CONFLICT, "User with this email already exists."),
    ACCOUNT_LOCKED(HttpStatus.FORBIDDEN, "User account is locked."),
    MISSING_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "Refresh token is required.");

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