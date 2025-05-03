package net.java.lms_backend.Repositrory;

import net.java.lms_backend.entity.QuizAttempt;
import net.java.lms_backend.entity.Submission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;


@Repository
public interface QuizAttemptRepository extends JpaRepository<QuizAttempt, Long> {
    public List<QuizAttempt> findByQuizId(Long quizId);
    public List<QuizAttempt> findByStudentIdAndQuiz_Course_Id(Long studentId, Long courseId);
}
