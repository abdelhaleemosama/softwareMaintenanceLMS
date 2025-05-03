package net.java.lms_backend.Service;

import net.java.lms_backend.entity.User;
import net.java.lms_backend.entity.Role;
import net.java.lms_backend.Repositrory.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class AdminService {

    private final UserRepository userRepository;

    @Autowired
    public AdminService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // Get all users in the system
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    // Promote a user to admin
    public User promoteToAdmin(Long userId) {
        Optional<User> userOpt = userRepository.findById(userId);
        if (userOpt.isPresent() && !userOpt.get().getRole().equals(Role.ADMIN)) {
            User user = userOpt.get();
            user.setRole(Role.ADMIN);
            return userRepository.save(user);
        }
        return null; // Return null if the user doesn't exist or is already an admin
    }

    // Assign a role to a user
    public boolean assignRole(Long userId, String role) {
        Optional<User> userOpt = userRepository.findById(userId);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            Role newRole = Role.valueOf(role.toUpperCase());

            // Check if the role is valid
            if (newRole == null) {
                return false; // Invalid role
            }

            user.setRole(newRole);
            userRepository.save(user);
            return true;
        }
        return false; // User not found
    }

    // Revoke a role from a user (set to 'STUDENT' or default role)
    public boolean revokeRole(Long userId, String role) {
        Optional<User> userOpt = userRepository.findById(userId);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            Role revokeRole = Role.valueOf(role.toUpperCase());

            // Check if the role matches the current user role
            if (user.getRole().equals(revokeRole)) {
                user.setRole(Role.STUDENT); // Default to STUDENT role
                userRepository.save(user);
                return true;
            }
        }
        return false; // User not found or role mismatch
    }

    // Deactivate a user account
    public boolean deactivateUser(Long userId) {
        Optional<User> userOpt = userRepository.findById(userId);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            user.setEnabled(false); // Disable the account
            userRepository.save(user);
            return true;
        }
        return false; // User not found
    }
}
