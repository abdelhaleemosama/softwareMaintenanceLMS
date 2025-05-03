package net.java.lms_backend.entity;

import jakarta.persistence.Entity;

@Entity
public class Admin extends User{
    public Admin(User user)
    {

        super(Role.ADMIN,new User());
    }
    public Admin()
    {
        super(Role.ADMIN,new User());
    }
}
