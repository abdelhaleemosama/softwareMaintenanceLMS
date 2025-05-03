package net.java.lms_backend.dto;

public class LoginRequestDTO {
    private String identifier; // email or username
    private String password;

    public String getPassword() {
        return password;
    }

    public String getIdentifier() {
        return identifier;
    }
    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }
    public void setPassword(String password) {
        this.password = password;
    }

    public String getUsername() {
        return identifier;
    }
}
