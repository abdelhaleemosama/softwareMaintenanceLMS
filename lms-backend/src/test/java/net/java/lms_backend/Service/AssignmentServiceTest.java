package net.java.lms_backend.Service;

import net.java.lms_backend.Repositrory.AssignmentRepository;
import net.java.lms_backend.Repositrory.CourseRepository;
import net.java.lms_backend.dto.AssignmentDTO;
import net.java.lms_backend.entity.Assignment;
import net.java.lms_backend.entity.Course;
import net.java.lms_backend.mapper.AssignmentMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.LocalDate;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AssignmentServiceTest {

    @Mock
    private AssignmentRepository assignmentRepository;

    @Mock
    private CourseRepository courseRepository;

    @Mock
    private AssignmentMapper assignmentMapper;

    @InjectMocks
    private AssignmentService assignmentService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testCreateAssignment() {
        AssignmentDTO dto = new AssignmentDTO("Test Assignment", "2024-12-31", 1L);
        Assignment assignment = new Assignment();
        Assignment savedAssignment = new Assignment();
        AssignmentDTO returnedDto = new AssignmentDTO("Test Assignment", "2024-12-31", 1L);
        returnedDto.setId(1L);

        when(assignmentMapper.toEntity(dto)).thenReturn(assignment);
        when(assignmentRepository.save(assignment)).thenReturn(savedAssignment);
        when(assignmentMapper.toDTO(savedAssignment)).thenReturn(returnedDto);

        AssignmentDTO result = assignmentService.createAssignment(dto);

        assertNotNull(result);
        assertEquals("Test Assignment", result.getTitle());
        assertEquals("2024-12-31", result.getDueDate());
        verify(assignmentRepository, times(1)).save(assignment);
    }

    @Test
    void testGetAssignmentById() {
        Assignment assignment = new Assignment();
        assignment.setId(1L);
        assignment.setTitle("Test Assignment");
        assignment.setDueDate(LocalDate.parse("2024-12-31"));

        AssignmentDTO dto = new AssignmentDTO("Test Assignment", "2024-12-31", 1L);
        dto.setId(1L);

        when(assignmentRepository.findById(1L)).thenReturn(Optional.of(assignment));
        when(assignmentMapper.toDTO(assignment)).thenReturn(dto);

        AssignmentDTO result = assignmentService.getAssignmentById(1L);

        assertNotNull(result);
        assertEquals(1L, result.getId());
        assertEquals("Test Assignment", result.getTitle());
        verify(assignmentRepository, times(1)).findById(1L);
    }

    @Test
    void testGetAllAssignments() {
        Assignment assignment1 = new Assignment();
        Assignment assignment2 = new Assignment();
        List<Assignment> assignments = Arrays.asList(assignment1, assignment2);

        AssignmentDTO dto1 = new AssignmentDTO("Assignment 1", "2024-12-30", 1L);
        AssignmentDTO dto2 = new AssignmentDTO("Assignment 2", "2024-12-31", 1L);

        when(assignmentRepository.findAll()).thenReturn(assignments);
        when(assignmentMapper.toDTO(assignment1)).thenReturn(dto1);
        when(assignmentMapper.toDTO(assignment2)).thenReturn(dto2);

        List<AssignmentDTO> result = assignmentService.getAllAssignments();

        assertNotNull(result);
        assertEquals(2, result.size());
        verify(assignmentRepository, times(1)).findAll();
    }

    @Test
    void testUpdateAssignment() {
        Assignment assignment = new Assignment();
        assignment.setId(1L);
        assignment.setTitle("Old Title");
        assignment.setDueDate(LocalDate.parse("2024-12-30"));

        Course course = new Course();
        course.setId(1L);

        AssignmentDTO dto = new AssignmentDTO("New Title", "2024-12-31", 1L);
        Assignment updatedAssignment = new Assignment();
        AssignmentDTO updatedDto = new AssignmentDTO("New Title", "2024-12-31", 1L);

        when(assignmentRepository.findById(1L)).thenReturn(Optional.of(assignment));
        when(courseRepository.findById(1L)).thenReturn(Optional.of(course));
        when(assignmentRepository.save(assignment)).thenReturn(updatedAssignment);
        when(assignmentMapper.toDTO(updatedAssignment)).thenReturn(updatedDto);

        AssignmentDTO result = assignmentService.updateAssignment(1L, dto);

        assertNotNull(result);
        assertEquals("New Title", result.getTitle());
        assertEquals("2024-12-31", result.getDueDate());
        verify(assignmentRepository, times(1)).save(assignment);
    }


    @Test
    void testDeleteAssignment() {
        when(assignmentRepository.existsById(1L)).thenReturn(true);

        assignmentService.deleteAssignment(1L);

        verify(assignmentRepository, times(1)).deleteById(1L);
    }

    @Test
    void testDeleteAssignment_NotFound() {
        when(assignmentRepository.existsById(1L)).thenReturn(false);

        Exception exception = assertThrows(IllegalArgumentException.class, () -> assignmentService.deleteAssignment(1L));
        assertEquals("Assignment not found with id: 1", exception.getMessage());
    }
}
