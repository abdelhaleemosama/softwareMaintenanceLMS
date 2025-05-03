package net.java.lms_backend.controller;

import net.java.lms_backend.Service.StudentService;
import net.java.lms_backend.Service.SubmissionService;
import net.java.lms_backend.dto.StudentDTO;
import net.java.lms_backend.dto.SubmissionDTO;
import net.java.lms_backend.entity.Submission;
import net.java.lms_backend.mapper.SubmissionMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/instructor")
public class InstructorController {
    private SubmissionService SubmissionService;
    public InstructorController(SubmissionService submissionService) {
        this.submissionService = submissionService;
    }
    @Autowired
    private SubmissionService submissionService;

    @Autowired
    private SubmissionMapper submissionMapper;

    @PostMapping("/{assignmentId}/submit")
    public ResponseEntity<SubmissionDTO> createSubmission(
            @PathVariable Long assignmentId,
            @RequestParam Long studentId,
            @RequestParam("file") MultipartFile file) {

        SubmissionDTO createdSubmission = submissionService.createSubmission(assignmentId, studentId, file);
        return new ResponseEntity<>(createdSubmission, HttpStatus.CREATED);
    }

    @GetMapping("/assignment/submissions/{assignment_id}")
    public ResponseEntity<List<SubmissionDTO>> getSubmissionsByAssignmentId(@PathVariable Long assignment_id) {
        List<SubmissionDTO> submissions = submissionService.getSubmissionsByAssignmentId(assignment_id);
        return ResponseEntity.ok(submissions);
    }


    @PatchMapping("/submissions/{id}/gradeAndFeedback")
    public SubmissionDTO updateSubmissionGrade(@PathVariable Long id,
                                               @RequestBody SubmissionDTO.SubmissionGradeAndFeedbackDTO submissionGradeAndFeedbackDTO) {
        double grade = submissionGradeAndFeedbackDTO.getGrade();
        String feedback = submissionGradeAndFeedbackDTO.getFeedback();
        return submissionService.patchSubmissionGradeAndFeedback(id, grade, feedback);
    }


    @GetMapping("/assignment/performance/{assignment_id}")
    public ResponseEntity<Map<String, Object>> getAssignmentPerformance(@PathVariable Long assignment_id) {

        double averageGrade = submissionService.getAverageGradeByAssignmentId(assignment_id);
        double nonGradedCount = submissionService.getNonGradedSubmissionsByAssignmentId(assignment_id);

        Map<String, Object> response = new HashMap<>();
        response.put("average grades", averageGrade);
        response.put("non graded submissions", nonGradedCount);

        return ResponseEntity.ok(response);
    }

    @GetMapping("course/{courseId}/student/{studentId}/submissions")
    public ResponseEntity<List<SubmissionDTO>> getSubmissionsByCourseAndStudent(@PathVariable Long courseId, @PathVariable Long studentId) {
        List<SubmissionDTO> submissions = submissionService.getSubmissionsByStudentIdAndCourseId(studentId, courseId);
        return ResponseEntity.ok(submissions);
    }

}
