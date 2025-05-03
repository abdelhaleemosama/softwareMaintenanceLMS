package net.java.lms_backend.mapper;

import net.java.lms_backend.dto.SubmissionDTO;
import net.java.lms_backend.entity.Submission;
import org.springframework.stereotype.Component;

@Component
public class SubmissionMapper {
    public Submission toEntity(SubmissionDTO dto) {
        Submission submission = new Submission();
        submission.setFileName(dto.getFileName());
        submission.setSubmittedAt(dto.getSubmittedAt());
        submission.setGrade(dto.getGrade());
        submission.setFeedback(dto.getFeedback());
        return submission;
    }

    public SubmissionDTO toDTO(Submission submission) {
        SubmissionDTO dto = new SubmissionDTO();
        dto.setId(submission.getId());
        dto.setFileName(submission.getFileName());
        dto.setSubmittedAt(submission.getSubmittedAt());
        dto.setAssignmentId(submission.getAssignment().getId());
        dto.setStudentId(submission.getStudent().getId());
        dto.setGrade(submission.getGrade());
        dto.setFeedback(submission.getFeedback());
        return dto;
    }
}