package net.java.lms_backend.mapper;

import net.java.lms_backend.dto.QuestionDTO;
import net.java.lms_backend.dto.QuestionOptionDTO;
import net.java.lms_backend.entity.Course;
import net.java.lms_backend.entity.Question;
import net.java.lms_backend.entity.QuestionOption;
import net.java.lms_backend.entity.QuestionType;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class QuestionMapperTest {

    @Test
    void testMapToQuestionDTO() {
        Course course = new Course();
        course.setId(1L);

        QuestionOption option1 = new QuestionOption();
        option1.setOptionContent("Option A");

        QuestionOption option2 = new QuestionOption();
        option2.setOptionContent("Option B");

        Question question = new Question();
        question.setId(1L);
        question.setContent("What is Java?");
        question.setCorrectAnswer("Option A");
        question.setType(QuestionType.MCQ);
        question.setCourse(course);
        question.setOptions(Arrays.asList(option1, option2));

        QuestionDTO questionDTO = QuestionMapper.mapToQuestionDTO(question);

        assertNotNull(questionDTO);
        assertEquals(1L, questionDTO.getId());
        assertEquals("What is Java?", questionDTO.getContent());
        assertEquals("Option A", questionDTO.getCorrectAnswer());
        assertEquals(QuestionType.MCQ, questionDTO.getType());
        assertEquals(1L, questionDTO.getCourseId());
        assertNotNull(questionDTO.getOptions());
        assertEquals(2, questionDTO.getOptions().size());
        assertEquals("Option A", questionDTO.getOptions().get(0).getOptionContent());
        assertEquals("Option B", questionDTO.getOptions().get(1).getOptionContent());
    }

    @Test
    void testMapToQuestion() {
        Course course = new Course();
        course.setId(1L);

        QuestionOptionDTO optionDTO1 = new QuestionOptionDTO("Option A");
        QuestionOptionDTO optionDTO2 = new QuestionOptionDTO("Option B");

        QuestionDTO questionDTO = new QuestionDTO(
                null,
                "What is Java?",
                "Option A",
                Arrays.asList(optionDTO1, optionDTO2),
                1L,
                QuestionType.MCQ
        );

        Question question = QuestionMapper.mapToQuestion(questionDTO, course);

        assertNotNull(question);
        assertEquals("What is Java?", question.getContent());
        assertEquals("Option A", question.getCorrectAnswer());
        assertEquals(QuestionType.MCQ, question.getType());
        assertEquals(course, question.getCourse());
        assertNotNull(question.getOptions());
        assertEquals(2, question.getOptions().size());
        assertEquals("Option A", question.getOptions().get(0).getOptionContent());
        assertEquals("Option B", question.getOptions().get(1).getOptionContent());
        assertEquals(question, question.getOptions().get(0).getQuestion());
        assertEquals(question, question.getOptions().get(1).getQuestion());
    }

    @Test
    void testMapToQuestionDTO_NoCourse() {
        QuestionOption option1 = new QuestionOption();
        option1.setOptionContent("Option A");

        QuestionOption option2 = new QuestionOption();
        option2.setOptionContent("Option B");

        Question question = new Question();
        question.setId(1L);
        question.setContent("What is Java?");
        question.setCorrectAnswer("Option A");
        question.setType(QuestionType.MCQ);
        question.setCourse(null); // No course assigned
        question.setOptions(Arrays.asList(option1, option2));

        QuestionDTO questionDTO = QuestionMapper.mapToQuestionDTO(question);

        assertNotNull(questionDTO);
        assertNull(questionDTO.getCourseId());
        assertEquals("What is Java?", questionDTO.getContent());
    }

    @Test
    void testMapToQuestion_NoOptions() {
        Course course = new Course();
        course.setId(1L);

        QuestionDTO questionDTO = new QuestionDTO(
                null,
                "What is Java?",
                "Option A",
                new ArrayList<QuestionOptionDTO>(),// No options
                1L,
                QuestionType.MCQ
        );

        Question question = QuestionMapper.mapToQuestion(questionDTO, course);

        assertNotNull(question);
        assertTrue(question.getOptions().isEmpty());

    }
}
