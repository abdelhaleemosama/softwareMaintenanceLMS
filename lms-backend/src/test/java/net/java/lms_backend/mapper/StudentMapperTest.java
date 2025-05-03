package net.java.lms_backend.mapper;

import net.java.lms_backend.dto.StudentDTO;
import net.java.lms_backend.entity.Student;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.*;

class StudentMapperTest {

    private Student student;
    private StudentDTO studentDTO;

    @BeforeEach
    void setUp() {
        student = new Student();
        student.setId(1L);
        student.setUsername("testUser");
        student.setEmail("test@example.com");

        studentDTO = new StudentDTO(1L, "testUser", "test@example.com");
    }

    @Test
    void mapToStudentDTO_WithValidStudent_ShouldMapAllFieldsCorrectly() {
        StudentDTO result = StudentMapper.mapToStudentDTO(student);

        assertNotNull(result);
        assertEquals(student.getId(), result.getId());
        assertEquals(student.getUsername(), result.getUsername());
        assertEquals(student.getEmail(), result.getEmail());
    }

    @Test
    void mapToStudentDTO_WithNullStudent_ShouldReturnNull() {
        StudentDTO result = StudentMapper.mapToStudentDTO(null);

        assertNull(result);
    }

    @Test
    void mapToStudentDTO_WithEmptyFields_ShouldMapCorrectly() {
        student.setUsername("");
        student.setEmail("");

        StudentDTO result = StudentMapper.mapToStudentDTO(student);

        assertNotNull(result);
        assertEquals(student.getId(), result.getId());
        assertEquals("", result.getUsername());
        assertEquals("", result.getEmail());
    }

    @Test
    void mapToStudentDTO_WithNullFields_ShouldMapCorrectly() {
        student.setUsername(null);
        student.setEmail(null);

        StudentDTO result = StudentMapper.mapToStudentDTO(student);

        assertNotNull(result);
        assertEquals(student.getId(), result.getId());
        assertNull(result.getUsername());
        assertNull(result.getEmail());
    }

    @Test
    void mapToStudent_WithValidDTO_ShouldMapAllFieldsCorrectly() {
        Student result = StudentMapper.mapToStudent(studentDTO);

        assertNotNull(result);
        assertEquals(studentDTO.getId(), result.getId());
        assertEquals(studentDTO.getUsername(), result.getUsername());
        assertEquals(studentDTO.getEmail(), result.getEmail());
    }

    @Test
    void mapToStudent_WithNullDTO_ShouldReturnNull() {
        Student result = StudentMapper.mapToStudent(null);

        assertNull(result);
    }

    @Test
    void mapToStudent_WithEmptyFields_ShouldMapCorrectly() {
        studentDTO = new StudentDTO(1L, "", "");

        Student result = StudentMapper.mapToStudent(studentDTO);

        assertNotNull(result);
        assertEquals(studentDTO.getId(), result.getId());
        assertEquals("", result.getUsername());
        assertEquals("", result.getEmail());
    }

    @Test
    void mapToStudent_WithNullFields_ShouldMapCorrectly() {
        studentDTO = new StudentDTO(1L, null, null);

        Student result = StudentMapper.mapToStudent(studentDTO);

        assertNotNull(result);
        assertEquals(studentDTO.getId(), result.getId());
        assertNull(result.getUsername());
        assertNull(result.getEmail());
    }
}