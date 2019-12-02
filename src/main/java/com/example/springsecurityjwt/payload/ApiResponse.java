package com.example.springsecurityjwt.payload;

public class ApiResponse {
    private Boolean success;
    private String message;

    public ApiResponse(Boolean success, String message)
    {
        this.message = message;
        this.success=success;
    }

    public Boolean getSuccess() {
        return success;
    }

    public void setSuccess(Boolean success) {
        this.success = success;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
