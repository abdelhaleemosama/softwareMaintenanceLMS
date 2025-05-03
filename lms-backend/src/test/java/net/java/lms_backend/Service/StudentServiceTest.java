package net.java.lms_backend.Service;

import net.java.lms_backend.Repositrory.*;
import net.java.lms_backend.dto.StudentDTO;
import net.java.lms_backend.entity.Student;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class StudentServiceTest {

    @Mock
    private StudentRepository studentRepository;
    @Mock
    private CourseRepository courseRepo;
    @Mock
    private UserRepository userRepo;
    @Mock
    private InstructorRepository instructorRepo;
    @Mock
    private LessonRepositery lessonRepo;
    @Mock
    private EnrollmentRepo enrollmentRepo;
    @Mock
    private AttendanceRepo attendanceRepo;

    @InjectMocks
    private StudentService studentService;

    private Student student;
    private StudentDTO studentDTO;

    @BeforeEach
    void setUp() {
        student = new Student();
        student.setId(1L);
        student.setUsername("testStudent");
        student.setEmail("test@example.com");

        studentDTO = new StudentDTO(1L, "testStudent", "test@example.com");
    }

    @Test
    void getAllStudents_Success() {
        List<Student> students = Arrays.asList(student);
        when(studentRepository.findAll()).thenReturn(students);

        List<StudentDTO> result = studentService.getAllStudents();

        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals(student.getUsername(), result.get(0).getUsername());
        assertEquals(student.getEmail(), result.get(0).getEmail());
        verify(studentRepository).findAll();
    }

    @Test
    void getAllStudents_EmptyList() {
        when(studentRepository.findAll()).thenReturn(Arrays.asList());

        List<StudentDTO> result = studentService.getAllStudents();

        assertNotNull(result);
        assertTrue(result.isEmpty());
        verify(studentRepository).findAll();
    }

    @Test
    void getStudentById_Success() {
        when(studentRepository.findById(1L)).thenReturn(Optional.of(student));

        StudentDTO result = studentService.getStudentById(1L);

        assertNotNull(result);
        assertEquals(student.getUsername(), result.getUsername());
        assertEquals(student.getEmail(), result.getEmail());
        verify(studentRepository).findById(1L);
    }

    @Test
    void getStudentById_NotFound() {
        when(studentRepository.findById(1L)).thenReturn(Optional.empty());

        StudentDTO result = studentService.getStudentById(1L);

        assertNull(result);
        verify(studentRepository).findById(1L);
    }

    @Test
    void createStudent_Success() {
        when(studentRepository.save(any(Student.class))).thenReturn(student);

        StudentDTO result = studentService.createStudent(studentDTO);

        assertNotNull(result);
        assertEquals(studentDTO.getUsername(), result.getUsername());
        assertEquals(studentDTO.getEmail(), result.getEmail());
        verify(studentRepository).save(any(Student.class));
    }

    @Test
    void updateStudent_Success() {
        when(studentRepository.findById(1L)).thenReturn(Optional.of(student));
        when(studentRepository.save(any(Student.class))).thenReturn(student);

        StudentDTO updateDTO = new StudentDTO(1L, "updatedName", "updated@example.com");

        StudentDTO result = studentService.updateStudent(1L, updateDTO);

        assertNotNull(result);
        assertEquals(updateDTO.getUsername(), result.getUsername());
        assertEquals(updateDTO.getEmail(), result.getEmail());
        verify(studentRepository).findById(1L);
        verify(studentRepository).save(any(Student.class));
    }

    @Test
    void updateStudent_NotFound() {
        when(studentRepository.findById(1L)).thenReturn(Optional.empty());

        StudentDTO result = studentService.updateStudent(1L, studentDTO);

        assertNull(result);
        verify(studentRepository).findById(1L);
        verify(studentRepository, never()).save(any(Student.class));
    }

    @Test
    void deleteStudent_Success() {
        when(studentRepository.existsById(1L)).thenReturn(true);
        doNothing().when(studentRepository).deleteById(1L);

        boolean result = studentService.deleteStudent(1L);

        assertTrue(result);
        verify(studentRepository).existsById(1L);
        verify(studentRepository).deleteById(1L);
    }

    @Test
    void deleteStudent_NotFound() {
        when(studentRepository.existsById(1L)).thenReturn(false);

        boolean result = studentService.deleteStudent(1L);

        assertFalse(result);
        verify(studentRepository).existsById(1L);
        verify(studentRepository, never()).deleteById(any());
    }
}