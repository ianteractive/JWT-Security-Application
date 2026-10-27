
package com.juan.authdemo.dto;

public class AuthResponse {

    private String token;
    private String refreshToken;
    private String tokenType;

    public AuthResponse() {
    }

    public AuthResponse(
            String token,
            String refreshToken,
            String tokenType) {
        this.token = token;
        this.refreshToken = refreshToken;
        this.tokenType = tokenType;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

}
