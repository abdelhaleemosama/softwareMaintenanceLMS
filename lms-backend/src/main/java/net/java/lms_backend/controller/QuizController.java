package net.java.lms_backend.controller;

import net.java.lms_backend.Service.QuizService;
import net.java.lms_backend.dto.QuizDTO;
import net.java.lms_backend.entity.Quiz;
import net.java.lms_backend.entity.QuizAttempt;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/quiz")
public class QuizController {
    private final QuizService quizService;

    public QuizController(QuizService quizService) {
        this.quizService = quizService;
    }

    @PostMapping("/create/{courseId}")
    public ResponseEntity<Quiz> createQuiz(@PathVariable Long courseId, @RequestBody QuizDTO quizDTO) {
        Quiz quiz = quizService.createQuiz(courseId, quizDTO);
        return ResponseEntity.ok(quiz);
    }

    @PostMapping("/attempt/{quizId}/student/{studentId}")
    public ResponseEntity<QuizAttempt> generateQuizAttempt(@PathVariable Long quizId , @PathVariable Long studentId) {
        QuizAttempt quizAttempt = quizService.generateQuizAttempt(quizId , studentId);
        return ResponseEntity.ok(quizAttempt);
    }

    @PatchMapping("/attempt/{quizAttemptId}")
    public ResponseEntity<Integer> updateQuizAttempt(
            @PathVariable Long quizAttemptId,
            @RequestBody Map<Long, String> answers) {
        int score = quizService.updateQuizAttempt(quizAttemptId, answers);
        return ResponseEntity.ok(score);
    }

    @GetMapping("/attempt/{quizAttemptId}")
    public ResponseEntity<QuizAttempt> getQuizAttempt(@PathVariable Long quizAttemptId) {
        QuizAttempt quizAttempt = quizService.getQuizAttempt(quizAttemptId);
        return ResponseEntity.ok(quizAttempt);
    }

    @GetMapping("/performance/{quizId}")
    public ResponseEntity<Integer> getQuizPerformance(@PathVariable Long quizId) {
        double performance = quizService.getAverageScoreByQuizId(quizId);
        return ResponseEntity.ok((int) performance);
    }

    @GetMapping("/course/{courseId}/student/{studentId}")
    public List<QuizAttempt> getQuizAttemptsByStudent( @PathVariable Long courseId, @PathVariable Long studentId) {
        return quizService.getQuizAttemptsByStudent(studentId,courseId);
    }

    @GetMapping("/course/{courseId}/student/{studentId}/averageScore")
    public Double getAverageScoreByStudent( @PathVariable Long courseId, @PathVariable Long studentId) {
        return quizService.getAverageScoreOfStudent(studentId,courseId);
    }

}
