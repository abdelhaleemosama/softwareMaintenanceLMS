package net.java.lms_backend.mapper;

import net.java.lms_backend.dto.QuizAttemptDTO;
import net.java.lms_backend.entity.Quiz;
import net.java.lms_backend.entity.QuizAttempt;
import net.java.lms_backend.entity.Student;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class QuizAttemptMapperTest {

    private Quiz quiz;
    private Student student;
    private QuizAttempt quizAttempt;

    @BeforeEach
    void setUp() {
        quiz = new Quiz();
        quiz.setId(1L);

        student = new Student();
        student.setId(1L);

        quizAttempt = new QuizAttempt();
        quizAttempt.setQuiz(quiz);
        quizAttempt.setStudent(student);
        quizAttempt.setScore(85);
    }

    @Test
    void toDTO_Success() {
        QuizAttemptDTO result = QuizAttemptMapper.toDTO(quizAttempt);

        assertNotNull(result);
        assertEquals(quiz.getId(), result.getQuizId());
        assertEquals(student.getId(), result.getStudentId());
        assertEquals(quizAttempt.getScore(), result.getScore());
    }

    @Test
    void toDTO_WithNullQuizAttempt() {
        assertThrows(NullPointerException.class, () -> {
            QuizAttemptMapper.toDTO(null);
        });
    }

    @Test
    void toDTO_WithNullQuiz() {
        quizAttempt.setQuiz(null);

        assertThrows(NullPointerException.class, () -> {
            QuizAttemptMapper.toDTO(quizAttempt);
        });
    }

    @Test
    void toDTO_WithNullStudent() {
        quizAttempt.setStudent(null);

        assertThrows(NullPointerException.class, () -> {
            QuizAttemptMapper.toDTO(quizAttempt);
        });
    }

    @Test
    void toDTO_WithScore() {
        quizAttempt.setScore(50);

        QuizAttemptDTO result = QuizAttemptMapper.toDTO(quizAttempt);

        assertNotNull(result);
        assertEquals(50, result.getScore());
    }
}