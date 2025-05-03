package net.java.lms_backend.entity;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table
public class ConfirmationToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String token;
    private LocalDateTime  createdDate;
    private LocalDateTime expiresDate;
    private LocalDateTime confirmedDate;
    @ManyToOne
    @JoinColumn(
            nullable = false,
            name="user_id"
    )
    private User user;

    public ConfirmationToken(User user,
                             String token,
                             LocalDateTime createdDate,
                             LocalDateTime expiresDate) {
        this.user = user;
        this.token = token;
        this.createdDate = createdDate;
        this.expiresDate = expiresDate;
    }

    public ConfirmationToken() {
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public LocalDateTime getCreatedDate() {
        return createdDate;
    }

    public void setCreatedDate(LocalDateTime createdDate) {
        this.createdDate = createdDate;
    }

    public LocalDateTime getConfirmedDate() {
        return confirmedDate;
    }

    public void setConfirmedDate(LocalDateTime confirmationDate) {
        this.confirmedDate = confirmationDate;
    }

    public LocalDateTime getExpiresDate() {
        return expiresDate;
    }

    public void setExpiresDate(LocalDateTime expiryDate) {
        this.expiresDate = expiryDate;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }
}

