package com.example.springsecurityjwt.payload;

import javax.validation.constraints.NotBlank;

public class LoginRequest {
    @NotBlank
    private String UsernameOrEmail;

    @NotBlank
    private String password;

    public String getUsernameOrEmail() {
        return UsernameOrEmail;
    }

    public void setUsernameOrEmail(String usernameOrEmail) {
        UsernameOrEmail = usernameOrEmail;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
