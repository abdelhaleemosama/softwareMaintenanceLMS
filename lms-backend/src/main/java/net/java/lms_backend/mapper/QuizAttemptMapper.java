package net.java.lms_backend.mapper;

import net.java.lms_backend.dto.QuizAttemptDTO;

public class QuizAttemptMapper {
    public static QuizAttemptDTO toDTO(net.java.lms_backend.entity.QuizAttempt quiz) {
        {
            QuizAttemptDTO quizDTO = new QuizAttemptDTO();
            quizDTO.setQuizId(quiz.getQuiz().getId());
            quizDTO.setStudentId(quiz.getStudent().getId());
            quizDTO.setScore(quiz.getScore());
            return quizDTO;
        }
    }

}
