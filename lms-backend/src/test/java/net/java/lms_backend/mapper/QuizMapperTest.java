package net.java.lms_backend.mapper;

import net.java.lms_backend.dto.QuizDTO;
import net.java.lms_backend.entity.Quiz;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.*;

class QuizMapperTest {

    private QuizDTO quizDTO;

    @BeforeEach
    void setUp() {
        quizDTO = new QuizDTO();
        quizDTO.setNumOfMCQ(5L);
        quizDTO.setNumOfTrueFalse(3L);
        quizDTO.setNumOfShortAnswer(2L);
    }

    @Test
    void toEntity_ShouldMapAllFieldsCorrectly() {
        Quiz result = QuizMapper.toEntity(quizDTO);

        assertNotNull(result);
        assertEquals(quizDTO.getNumOfMCQ(), result.getNumOfMCQ());
        assertEquals(quizDTO.getNumOfTrueFalse(), result.getNumOfTrueFalse());
        assertEquals(quizDTO.getNumOfShortAnswer(), result.getNumOfShortAnswer());
    }


    @Test
    void toEntity_WithMaxValues_ShouldMapCorrectly() {
        quizDTO.setNumOfMCQ(Long.MAX_VALUE);
        quizDTO.setNumOfTrueFalse(Long.MAX_VALUE);
        quizDTO.setNumOfShortAnswer(Long.MAX_VALUE);

        Quiz result = QuizMapper.toEntity(quizDTO);

        assertNotNull(result);
        assertEquals(Long.MAX_VALUE, result.getNumOfMCQ());
        assertEquals(Long.MAX_VALUE, result.getNumOfTrueFalse());
        assertEquals(Long.MAX_VALUE, result.getNumOfShortAnswer());
    }


    @Test
    void toEntity_WithNullDTO_ShouldThrowNullPointerException() {
        assertThrows(NullPointerException.class, () -> {
            QuizMapper.toEntity(null);
        });
    }
}