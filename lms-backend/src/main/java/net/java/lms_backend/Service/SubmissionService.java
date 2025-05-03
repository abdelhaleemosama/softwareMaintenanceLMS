package net.java.lms_backend.Service;

import lombok.Getter;
import lombok.Setter;
import net.java.lms_backend.Repositrory.*;
import net.java.lms_backend.dto.SubmissionDTO;
import net.java.lms_backend.entity.Assignment;
import net.java.lms_backend.entity.Submission;
import net.java.lms_backend.mapper.SubmissionMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;


@Getter
@Setter
@Service
public class SubmissionService {
    @Autowired
    private SubmissionRepository submissionRepository;

    @Autowired
    private AssignmentRepository assignmentRepository;

    @Autowired
    private StudentRepository studentRepository;

    private final SubmissionMapper submissionMapper;

    public SubmissionService(SubmissionRepository submissionRepository,
                             StudentRepository studentRepository,
                             AssignmentRepository assignmentRepository,
                             SubmissionMapper submissionMapper) {
        this.submissionRepository = submissionRepository;
        this.studentRepository = studentRepository;
        this.assignmentRepository = assignmentRepository;
        this.submissionMapper = submissionMapper;
    }

    public SubmissionDTO createSubmission(Long assignmentId, Long studentId, MultipartFile file) {
        if (file.isEmpty()) {
            throw new IllegalArgumentException("File must not be empty.");
        }

        // Save the file locally
        String fileName = saveFile(file);

        Submission submission = new Submission();
        submission.setFileName(fileName);
        submission.setSubmittedAt(LocalDateTime.now());
        submission.setStudent(studentRepository.findById(studentId)
                .orElseThrow(() -> new IllegalArgumentException("Student not found")));
        submission.setAssignment(assignmentRepository.findById(assignmentId)
                .orElseThrow(() -> new IllegalArgumentException("Assignment not found")));

        Submission savedSubmission = submissionRepository.save(submission);
        return new SubmissionDTO(savedSubmission.getId(), savedSubmission.getSubmittedAt(), studentId, assignmentId, fileName);
    }

    private String saveFile(MultipartFile file) {
        try {
            // Define the directory where files will be saved
            String uploadDir = "uploads/";
            String fileName = file.getOriginalFilename();

            // Ensure the directory exists
            Path uploadPath = Paths.get(uploadDir);
            if (!Files.exists(uploadPath)) {
                Files.createDirectories(uploadPath);
            }

            // Save the file
            Path filePath = uploadPath.resolve(fileName);
            Files.copy(file.getInputStream(), filePath, StandardCopyOption.REPLACE_EXISTING);

            return fileName;
        } catch (IOException e) {
            throw new RuntimeException("Could not save file. Error: " + e.getMessage());
        }
    }

    public List<SubmissionDTO> getAllSubmissions() {
        return submissionRepository.findAll().stream()
                .map(submissionMapper::toDTO)
                .collect(Collectors.toList());
    }

    public SubmissionDTO getSubmissionById(Long id) {
        Submission submission = submissionRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Submission not found"));
        return submissionMapper.toDTO(submission);
    }

    public void deleteSubmission(Long id) {
        if (!submissionRepository.existsById(id)) {
            throw new IllegalArgumentException("Submission not found");
        }
        submissionRepository.deleteById(id);
    }

    public SubmissionDTO patchSubmissionGradeAndFeedback(Long submissionId, Double grade, String feedback) {
        if (grade == null || grade < 0) {
            throw new IllegalArgumentException("Grade must be greater than or equal to 0.");
        }

        Submission submission = submissionRepository.findById(submissionId)
                .orElseThrow(() -> new IllegalArgumentException("Submission not found"));

        submission.setGrade(grade);
        submission.setFeedback(feedback);
        Submission updatedSubmission = submissionRepository.save(submission);

        return submissionMapper.toDTO(updatedSubmission);
    }
    public List<SubmissionDTO> getSubmissionsByAssignmentId(Long assignmentId) {
        List<Submission> submissions = submissionRepository.findByAssignmentId(assignmentId);
        return submissions.stream()
                .map(submissionMapper::toDTO)
                .collect(Collectors.toList());
    }

    public double getAverageGradeByAssignmentId(Long assignmentId) {
        List<Submission> submissions = submissionRepository.findByAssignmentId(assignmentId);

        // Filter out submissions with null grades
        List<Submission> submissionsWithGrades = submissions.stream()
                .filter(submission -> submission.getGrade() != null)
                .collect(Collectors.toList());

        if (submissionsWithGrades.isEmpty()) {
            throw new IllegalArgumentException("No grades available for this assignment.");
        }

        double totalGrade = submissionsWithGrades.stream()
                .mapToDouble(Submission::getGrade)
                .sum();

        return totalGrade / submissionsWithGrades.size();
    }

    public int getTotalSubmissionsByAssignmentId(Long assignmentId) {
        return submissionRepository.findByAssignmentId(assignmentId).size();
    }

    public double getNonGradedSubmissionsByAssignmentId(Long assignmentId) {
        List<Submission> submissions = submissionRepository.findByAssignmentId(assignmentId);

        // Filter out submissions with null grades
        List<Submission> NonGradedSubmissions = submissions.stream()
                .filter(submission -> submission.getGrade() == null)
                .collect(Collectors.toList());

        return NonGradedSubmissions.size();
    }

    public List <SubmissionDTO> getSubmissionsByStudentIdAndCourseId(Long studentId, Long assignmentId) {
        List<Submission> submissions = submissionRepository.findByStudentIdAndAssignment_Course_Id(assignmentId, studentId);
        return submissions.stream()
                .map(submissionMapper::toDTO)
                .collect(Collectors.toList());

    }
}
