package net.java.lms_backend.mapper;

import net.java.lms_backend.dto.SubmissionDTO;
import net.java.lms_backend.entity.Assignment;
import net.java.lms_backend.entity.Student;
import net.java.lms_backend.entity.Submission;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class SubmissionMapperTest {

    @InjectMocks
    private SubmissionMapper submissionMapper;

    private SubmissionDTO submissionDTO;
    private Submission submission;
    private Assignment assignment;
    private Student student;
    private LocalDateTime submittedAt;

    @BeforeEach
    void setUp() {
        submittedAt = LocalDateTime.now();

        submissionDTO = new SubmissionDTO();
        submissionDTO.setId(1L);
        submissionDTO.setFileName("test.pdf");
        submissionDTO.setSubmittedAt(submittedAt);
        submissionDTO.setAssignmentId(1L);
        submissionDTO.setStudentId(1L);
        submissionDTO.setGrade(85.5);
        submissionDTO.setFeedback("Good work!");

        assignment = new Assignment();
        assignment.setId(1L);

        student = new Student();
        student.setId(1L);

        submission = new Submission();
        submission.setId(1L);
        submission.setFileName("test.pdf");
        submission.setSubmittedAt(submittedAt);
        submission.setAssignment(assignment);
        submission.setStudent(student);
        submission.setGrade(85.5);
        submission.setFeedback("Good work!");
    }

    @Test
    void toEntity_WithValidDTO_ShouldMapAllFieldsCorrectly() {
        Submission result = submissionMapper.toEntity(submissionDTO);

        assertNotNull(result);
        assertEquals(submissionDTO.getFileName(), result.getFileName());
        assertEquals(submissionDTO.getSubmittedAt(), result.getSubmittedAt());
        assertEquals(submissionDTO.getGrade(), result.getGrade());
        assertEquals(submissionDTO.getFeedback(), result.getFeedback());
    }

    @Test
    void toEntity_WithNullFields_ShouldMapCorrectly() {
        submissionDTO.setFileName(null);
        submissionDTO.setSubmittedAt(null);
        submissionDTO.setGrade(null);
        submissionDTO.setFeedback(null);

        Submission result = submissionMapper.toEntity(submissionDTO);

        assertNotNull(result);
        assertNull(result.getFileName());
        assertNull(result.getSubmittedAt());
        assertNull(result.getGrade());
        assertNull(result.getFeedback());
    }

    @Test
    void toDTO_WithValidSubmission_ShouldMapAllFieldsCorrectly() {
        SubmissionDTO result = submissionMapper.toDTO(submission);

        assertNotNull(result);
        assertEquals(submission.getId(), result.getId());
        assertEquals(submission.getFileName(), result.getFileName());
        assertEquals(submission.getSubmittedAt(), result.getSubmittedAt());
        assertEquals(submission.getAssignment().getId(), result.getAssignmentId());
        assertEquals(submission.getStudent().getId(), result.getStudentId());
        assertEquals(submission.getGrade(), result.getGrade());
        assertEquals(submission.getFeedback(), result.getFeedback());
    }

    @Test
    void toDTO_WithNullFields_ShouldMapCorrectly() {
        submission.setFileName(null);
        submission.setSubmittedAt(null);
        submission.setGrade(null);
        submission.setFeedback(null);

        SubmissionDTO result = submissionMapper.toDTO(submission);

        assertNotNull(result);
        assertNull(result.getFileName());
        assertNull(result.getSubmittedAt());
        assertNull(result.getGrade());
        assertNull(result.getFeedback());
    }

    @Test
    void toDTO_WithNullAssignment_ShouldThrowNullPointerException() {
        submission.setAssignment(null);

        assertThrows(NullPointerException.class, () -> {
            submissionMapper.toDTO(submission);
        });
    }

    @Test
    void toDTO_WithNullStudent_ShouldThrowNullPointerException() {
        submission.setStudent(null);

        assertThrows(NullPointerException.class, () -> {
            submissionMapper.toDTO(submission);
        });
    }

    @Test
    void toEntity_WithNullDTO_ShouldThrowNullPointerException() {
        assertThrows(NullPointerException.class, () -> {
            submissionMapper.toEntity(null);
        });
    }

    @Test
    void toDTO_WithNullSubmission_ShouldThrowNullPointerException() {
        assertThrows(NullPointerException.class, () -> {
            submissionMapper.toDTO(null);
        });
    }
}