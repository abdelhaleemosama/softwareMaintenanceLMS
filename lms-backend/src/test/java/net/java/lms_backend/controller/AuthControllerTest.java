//package net.java.lms_backend.controller;
//
//import net.java.lms_backend.Service.UserService;
//import net.java.lms_backend.dto.LoginRequestDTO;
//import net.java.lms_backend.entity.User;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//import org.mockito.InjectMocks;
//import org.mockito.Mock;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.boot.test.context.SpringBootTest;
//
//import static org.mockito.Mockito.*;
//import static org.junit.jupiter.api.Assertions.*;
//
//@SpringBootTest
//public class AuthControllerTest {
//
//    @Mock
//    private UserService userService; // Mocking the UserService
//
//    @InjectMocks
//    private AuthController authController; // Injecting mocked service into the controller
//
//    private User mockUser;
//    private LoginRequestDTO loginRequestDTO;
//
//    @BeforeEach
//    public void setup() {
//        // Setting up test data
//        mockUser = new User();
//        mockUser.setUsername("Joo91");
//        mockUser.setPassword("12345");
//        mockUser.setEmail("yousefkarem91@gmail.com");
//
//        loginRequestDTO = new LoginRequestDTO();
//        loginRequestDTO.setIdentifier("Joo91");
//        loginRequestDTO.setPassword("12345");
//    }
//
//    @Test
//    public void testLogin_Success() {
//        // Arrange
//        when(userService.login(any())).thenReturn(true); // Mock the login service method to return true for success
//
//        // Act
//        ResponseEntity<String> response = authController.login(loginRequestDTO);
//
//        // Assert
//        assertEquals(HttpStatus.OK, response.getStatusCode());
//        assertEquals("Login successful!", response.getBody());
//        verify(userService, times(1)).login(any()); // Ensure the login method is called once
//    }
//
//    @Test
//    public void testLogin_Failure() {
//        // Arrange
//        when(userService.login(any())).thenReturn(false); // Mock the login service method to return false for failure
//
//        // Act
//        ResponseEntity<String> response = authController.login(loginRequestDTO);
//
//        // Assert
//        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
//        assertEquals("Invalid credentials", response.getBody());
//        verify(userService, times(1)).login(any()); // Ensure the login method is called once
//    }
//
//    @Test
//    public void testRegister_Success() {
//        // Arrange
//        when(userService.registerUser(any(User.class))).thenReturn(mockUser); // Mock the register service method
//
//        // Act
//        ResponseEntity<User> response = authController.register(mockUser);
//
//        // Assert
//        assertEquals(HttpStatus.CREATED, response.getStatusCode());
//        assertEquals(mockUser, response.getBody());
//        verify(userService, times(1)).registerUser(any()); // Ensure the register method is called once
//    }
//
//    @Test
//    public void testRegister_Failure() {
//        // In case there's a failure scenario (e.g., duplicate username/email)
//        when(userService.registerUser(any(User.class))).thenThrow(new RuntimeException("Username already taken"));
//
//        // Act and Assert
//        try {
//            authController.register(mockUser);
//            fail("Expected exception to be thrown");
//        } catch (RuntimeException e) {
//            assertEquals("Username already taken", e.getMessage());
//        }
//
//        verify(userService, times(1)).registerUser(any()); // Ensure the register method is called once
//    }
//}
