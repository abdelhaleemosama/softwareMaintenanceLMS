package net.java.lms_backend.Service;

import net.java.lms_backend.Repositrory.AssignmentRepository;
import net.java.lms_backend.Repositrory.StudentRepository;
import net.java.lms_backend.Repositrory.SubmissionRepository;
import net.java.lms_backend.dto.SubmissionDTO;
import net.java.lms_backend.entity.Assignment;
import net.java.lms_backend.entity.Student;
import net.java.lms_backend.entity.Submission;
import net.java.lms_backend.mapper.SubmissionMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SubmissionServiceTest {

    @Mock
    private SubmissionRepository submissionRepository;

    @Mock
    private AssignmentRepository assignmentRepository;

    @Mock
    private StudentRepository studentRepository;

    @Mock
    private SubmissionMapper submissionMapper;

    @InjectMocks
    private SubmissionService submissionService;

    private Submission submission;
    private SubmissionDTO submissionDTO;
    private Student student;
    private Assignment assignment;
    private MultipartFile multipartFile;

    @BeforeEach
    void setUp() {
        student = new Student();
        student.setId(1L);

        assignment = new Assignment();
        assignment.setId(1L);

        submission = new Submission();
        submission.setId(1L);
        submission.setFileName("test.pdf");
        submission.setSubmittedAt(LocalDateTime.now());
        submission.setStudent(student);
        submission.setAssignment(assignment);
        submission.setGrade(85.0);
        submission.setFeedback("Good work");

        submissionDTO = new SubmissionDTO(1L, LocalDateTime.now(), 1L, 1L, "test.pdf");

        multipartFile = new MockMultipartFile(
                "file",
                "test.pdf",
                "application/pdf",
                "test content".getBytes()
        );
    }

    @Test
    void createSubmission_Success() {
        when(studentRepository.findById(1L)).thenReturn(Optional.of(student));
        when(assignmentRepository.findById(1L)).thenReturn(Optional.of(assignment));
        when(submissionRepository.save(any(Submission.class))).thenReturn(submission);

        SubmissionDTO result = submissionService.createSubmission(1L, 1L, multipartFile);

        assertNotNull(result);
        assertEquals(submission.getId(), result.getId());
        assertEquals(submission.getFileName(), result.getFileName());
        verify(submissionRepository).save(any(Submission.class));
    }

    @Test
    void createSubmission_EmptyFile() {
        MultipartFile emptyFile = new MockMultipartFile("file", new byte[0]);

        assertThrows(IllegalArgumentException.class, () ->
                submissionService.createSubmission(1L, 1L, emptyFile));
    }

    @Test
    void getAllSubmissions_Success() {
        List<Submission> submissions = Arrays.asList(submission);
        when(submissionRepository.findAll()).thenReturn(submissions);
        when(submissionMapper.toDTO(any(Submission.class))).thenReturn(submissionDTO);

        List<SubmissionDTO> result = submissionService.getAllSubmissions();

        assertNotNull(result);
        assertFalse(result.isEmpty());
        assertEquals(1, result.size());
        verify(submissionRepository).findAll();
    }

    @Test
    void getSubmissionById_Success() {
        when(submissionRepository.findById(1L)).thenReturn(Optional.of(submission));
        when(submissionMapper.toDTO(submission)).thenReturn(submissionDTO);

        SubmissionDTO result = submissionService.getSubmissionById(1L);

        assertNotNull(result);
        assertEquals(submissionDTO.getId(), result.getId());
        verify(submissionRepository).findById(1L);
    }

    @Test
    void getSubmissionById_NotFound() {
        when(submissionRepository.findById(1L)).thenReturn(Optional.empty());

        assertThrows(IllegalArgumentException.class, () ->
                submissionService.getSubmissionById(1L));
    }

    @Test
    void deleteSubmission_Success() {
        when(submissionRepository.existsById(1L)).thenReturn(true);

        assertDoesNotThrow(() -> submissionService.deleteSubmission(1L));
        verify(submissionRepository).deleteById(1L);
    }

    @Test
    void deleteSubmission_NotFound() {
        when(submissionRepository.existsById(1L)).thenReturn(false);

        assertThrows(IllegalArgumentException.class, () ->
                submissionService.deleteSubmission(1L));
    }

    @Test
    void patchSubmissionGradeAndFeedback_Success() {
        when(submissionRepository.findById(1L)).thenReturn(Optional.of(submission));
        when(submissionRepository.save(any(Submission.class))).thenReturn(submission);
        when(submissionMapper.toDTO(submission)).thenReturn(submissionDTO);

        SubmissionDTO result = submissionService.patchSubmissionGradeAndFeedback(1L, 90.0, "Excellent");

        assertNotNull(result);
        verify(submissionRepository).save(any(Submission.class));
    }

    @Test
    void patchSubmissionGradeAndFeedback_InvalidGrade() {
        assertThrows(IllegalArgumentException.class, () ->
                submissionService.patchSubmissionGradeAndFeedback(1L, -1.0, "Invalid"));
    }

    @Test
    void getAverageGradeByAssignmentId_Success() {
        List<Submission> submissions = Arrays.asList(
                createSubmissionWithGrade(80.0),
                createSubmissionWithGrade(90.0)
        );
        when(submissionRepository.findByAssignmentId(1L)).thenReturn(submissions);

        double average = submissionService.getAverageGradeByAssignmentId(1L);

        assertEquals(85.0, average);
    }

    @Test
    void getTotalSubmissionsByAssignmentId_Success() {
        List<Submission> submissions = Arrays.asList(submission, submission);
        when(submissionRepository.findByAssignmentId(1L)).thenReturn(submissions);

        int total = submissionService.getTotalSubmissionsByAssignmentId(1L);

        assertEquals(2, total);
    }

    @Test
    void getSubmissionsByStudentIdAndCourseId_Success() {
        List<Submission> submissions = Arrays.asList(submission);
        when(submissionRepository.findByStudentIdAndAssignment_Course_Id(1L, 1L))
                .thenReturn(submissions);
        when(submissionMapper.toDTO(any(Submission.class))).thenReturn(submissionDTO);

        List<SubmissionDTO> result = submissionService.getSubmissionsByStudentIdAndCourseId(1L, 1L);

        assertNotNull(result);
        assertFalse(result.isEmpty());
        assertEquals(1, result.size());
    }

    private Submission createSubmissionWithGrade(Double grade) {
        Submission submission = new Submission();
        submission.setGrade(grade);
        return submission;
    }
}