package net.java.lms_backend.entity;
import jakarta.persistence.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;


@Entity
@Table(name = "users")
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column
    private String firstName;
    @Column
    private String lastName;
    @Column(unique=true,nullable=false)
    private String username;
    @Column(nullable=false)
    private String password; // This will store the hashed password
    @Column(unique=true)

    private String email;

    private boolean initialAdmin;
    public boolean isInitialAdmin() {
        return initialAdmin;
    }

    public void setInitialAdmin(boolean initialAdmin) {
        this.initialAdmin = initialAdmin;
    }
    public boolean isLocked() {
        return locked;
    }

    public void setLocked(boolean locked) {
        this.locked = locked;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public Role getRole() {
        return role;
    }

    @Column
    private boolean locked=false;
    @Column
    private boolean enabled=false;

    public void setUserRole(net.java.lms_backend.entity.Role userRole) {
        this.role = userRole;
    }

    @Enumerated(EnumType.STRING)
    private Role role= Role.USER;
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Course> courses=new ArrayList<Course>();


    public User(
                String firstName,
                String lastName,
                String username,
                String password,
                String email,
                boolean locked,
                boolean enabled) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.username = username;
        this.password = password;
        this.email = email;
        this.locked = locked;
        this.enabled = enabled;
    }
    public User(Role role,User user)
    {
        this.role=role;
        firstName=user.firstName;
        lastName=user.lastName;
        username=user.username;
        password=user.password;
        email=user.email;
    }

    public User() {

    }

    public String toString() {
        return "User{" +
                "id=" + id +
                ", firstname='" + firstName + '\'' +
                ", lastname='" + lastName + '\'' +
                ", username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", role='" +role.name()+ '\'' +
                '}';
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority(role.name());
        return Collections.singletonList(authority);
    }


    @Override
    public boolean isAccountNonExpired() {
        return true ;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !locked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    public String getPassword() {return password;}
    public Long getId() {return id;}
    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }
    public String getFirstName() {
        return firstName;
    }
    public String getLastName() {
        return lastName;
    }


    public void setUsername(String username) {
        this.username=username;
    }
    public void setEmail(String email) {
        this.email=email;
    }

    public void setId(Long id) {this.id=id;}
    public void setFirstName(String firstName) {this.firstName=firstName;}
    public void setLastName(String lastName) {this.lastName=lastName;}
    public void setPassword(String password) {this.password=password;}

}
