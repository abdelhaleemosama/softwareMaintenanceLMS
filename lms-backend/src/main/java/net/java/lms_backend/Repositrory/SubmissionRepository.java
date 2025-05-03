package net.java.lms_backend.Repositrory;

import net.java.lms_backend.entity.Submission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SubmissionRepository extends JpaRepository<Submission, Long> {
    public List<Submission> findByAssignmentId(Long assignmentId);
    List<Submission> findByStudentIdAndAssignment_Course_Id(Long studentId, Long courseId);
}
