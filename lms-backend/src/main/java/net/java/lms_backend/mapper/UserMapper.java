package net.java.lms_backend.mapper;

import net.java.lms_backend.dto.LoginRequestDTO;
import net.java.lms_backend.dto.RegisterDTO;
import net.java.lms_backend.entity.User;
import net.java.lms_backend.entity.Role;


public class UserMapper {
    public static User ToUserRegister(RegisterDTO rs) {
        User user = new User();
        user.setUserRole(Role.USER);
        user.setEmail(rs.getEmail());
        user.setPassword(rs.getPassword());
        user.setUsername(rs.getUsername());
        user.setFirstName(rs.getFirstname());
        user.setLastName(rs.getLastname());
        return user;
    }
    public static User ToUserLogin(LoginRequestDTO login) {
        User user = new User();
        user.setUsername(login.getIdentifier());
        user.setEmail(login.getIdentifier());
        user.setPassword(login.getPassword());
        return user;
    }

}
