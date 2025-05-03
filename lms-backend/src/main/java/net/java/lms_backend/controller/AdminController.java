package net.java.lms_backend.controller;

import net.java.lms_backend.entity.User;
import net.java.lms_backend.Service.AdminService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final AdminService adminService;

    @Autowired
    public AdminController(AdminService adminService) {
        this.adminService = adminService;
    }

    // Get all users in the system
    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = adminService.getAllUsers();
        return ResponseEntity.ok(users);
    }

    // Promote a user to admin
    @PostMapping("/promote/{userId}")
    public ResponseEntity<User> promoteToAdmin(@PathVariable Long userId) {
        User promotedUser = adminService.promoteToAdmin(userId);
        if (promotedUser != null) {
            return ResponseEntity.ok(promotedUser);
        }
        return ResponseEntity.badRequest().build();
    }

    // Assign a specific role to a user
    @PostMapping("/assign-role/{userId}")
    public ResponseEntity<String> assignRole(@PathVariable Long userId, @RequestParam String role) {
        boolean success = adminService.assignRole(userId, role);
        if (success) {
            return ResponseEntity.ok("Role assigned successfully");
        }
        return ResponseEntity.badRequest().body("Failed to assign role. Invalid role or user.");
    }

    // Revoke a role from a user
    @PostMapping("/revoke-role/{userId}")
    public ResponseEntity<String> revokeRole(@PathVariable Long userId, @RequestParam String role) {
        boolean success = adminService.revokeRole(userId, role);
        if (success) {
            return ResponseEntity.ok("Role revoked successfully");
        }
        return ResponseEntity.badRequest().body("Failed to revoke role. Invalid role or user.");
    }

    // Deactivate a user account
    @PostMapping("/deactivate/{userId}")
    public ResponseEntity<String> deactivateUser(@PathVariable Long userId) {
        boolean success = adminService.deactivateUser(userId);
        if (success) {
            return ResponseEntity.ok("User deactivated successfully");
        }
        return ResponseEntity.badRequest().body("Failed to deactivate user. User not found.");
    }
}
