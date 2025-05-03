package net.java.lms_backend.mapper;

import net.java.lms_backend.Repositrory.CourseRepository;
import net.java.lms_backend.dto.AssignmentDTO;
import net.java.lms_backend.entity.Assignment;
import net.java.lms_backend.entity.Course;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.LocalDate;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AssignmentMapperTest {

    @InjectMocks
    private AssignmentMapper assignmentMapper;

    @Mock
    private CourseRepository courseRepository;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testToEntity_WithValidCourseId() {
        AssignmentDTO dto = new AssignmentDTO();
        dto.setTitle("Test Assignment");
        dto.setDueDate("2024-12-31");
        dto.setCourseId(1L);

        Course course = new Course();
        course.setId(1L);

        when(courseRepository.findById(1L)).thenReturn(Optional.of(course));

        Assignment assignment = assignmentMapper.toEntity(dto);

        assertNotNull(assignment);
        assertEquals("Test Assignment", assignment.getTitle());
        assertEquals(LocalDate.of(2024, 12, 31), assignment.getDueDate());
        assertEquals(course, assignment.getCourse());
    }

    @Test
    void testToEntity_WithInvalidCourseId() {
        AssignmentDTO dto = new AssignmentDTO();
        dto.setTitle("Test Assignment");
        dto.setDueDate("2024-12-31");
        dto.setCourseId(999L);

        when(courseRepository.findById(999L)).thenReturn(Optional.empty());

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            assignmentMapper.toEntity(dto);
        });

        assertEquals("Invalid course ID: 999", exception.getMessage());
    }

    @Test
    void testToEntity_WithoutCourseId() {
        AssignmentDTO dto = new AssignmentDTO();
        dto.setTitle("Test Assignment");
        dto.setDueDate("2024-12-31");
        dto.setCourseId(null);

        Assignment assignment = assignmentMapper.toEntity(dto);

        assertNotNull(assignment);
        assertEquals("Test Assignment", assignment.getTitle());
        assertEquals(LocalDate.of(2024, 12, 31), assignment.getDueDate());
        assertNull(assignment.getCourse());
    }

    @Test
    void testToDTO_WithCourse() {
        Course course = new Course();
        course.setId(1L);

        Assignment assignment = new Assignment();
        assignment.setId(1L);
        assignment.setTitle("Test Assignment");
        assignment.setDueDate(LocalDate.of(2024, 12, 31));
        assignment.setCourse(course);

        AssignmentDTO dto = assignmentMapper.toDTO(assignment);

        assertNotNull(dto);
        assertEquals(1L, dto.getId());
        assertEquals("Test Assignment", dto.getTitle());
        assertEquals("2024-12-31", dto.getDueDate());
        assertEquals(1L, dto.getCourseId());
    }

    @Test
    void testToDTO_WithoutCourse() {
        Assignment assignment = new Assignment();
        assignment.setId(1L);
        assignment.setTitle("Test Assignment");
        assignment.setDueDate(LocalDate.of(2024, 12, 31));
        assignment.setCourse(null);

        AssignmentDTO dto = assignmentMapper.toDTO(assignment);

        assertNotNull(dto);
        assertEquals(1L, dto.getId());
        assertEquals("Test Assignment", dto.getTitle());
        assertEquals("2024-12-31", dto.getDueDate());
        assertNull(dto.getCourseId());
    }
}
