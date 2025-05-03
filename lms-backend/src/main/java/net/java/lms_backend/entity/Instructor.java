package net.java.lms_backend.entity;
import jakarta.persistence.*;
import jakarta.persistence.Entity;

import java.util.List;

@Entity
public class Instructor extends User {
    @OneToMany(mappedBy = "instructor", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Course> courses; // List to hold courses for the instructor

    public Instructor(User user) {
        super  (Role.INSTRUCTOR,user);
    }

    public Instructor()
    {
        super(Role.INSTRUCTOR,new User());
    }


}
