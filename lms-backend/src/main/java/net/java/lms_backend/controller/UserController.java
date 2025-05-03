package net.java.lms_backend.controller;

import net.java.lms_backend.Service.UserService;
import net.java.lms_backend.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/user")
public class UserController {
    @Autowired
    UserService userService;

    @GetMapping("/view/{id}")
    public ResponseEntity<String> view(@PathVariable long id)
    {
        Optional<User> user=userService.getUser(id);
        if(user!=null)
        {
            return ResponseEntity.ok(user.toString());
        }
        return ResponseEntity.notFound().build();
    }
}