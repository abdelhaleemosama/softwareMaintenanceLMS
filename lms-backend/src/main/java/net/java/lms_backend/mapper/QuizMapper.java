package net.java.lms_backend.mapper;

import net.java.lms_backend.dto.QuizDTO;
import net.java.lms_backend.entity.Quiz;

public class QuizMapper {
    public static Quiz toEntity(QuizDTO quizDTO) {
        Quiz quiz = new Quiz();
        quiz.setNumOfMCQ(quizDTO.getNumOfMCQ());
        quiz.setNumOfTrueFalse(quizDTO.getNumOfTrueFalse());
        quiz.setNumOfShortAnswer(quizDTO.getNumOfShortAnswer());
        return quiz;
    }
}
