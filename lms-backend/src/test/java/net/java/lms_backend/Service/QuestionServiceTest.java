package net.java.lms_backend.Service;

import net.java.lms_backend.Repositrory.CourseRepository;
import net.java.lms_backend.Repositrory.QuestionRepository;
import net.java.lms_backend.dto.QuestionDTO;
import net.java.lms_backend.dto.QuestionOptionDTO;
import net.java.lms_backend.entity.Course;
import net.java.lms_backend.entity.Question;
import net.java.lms_backend.entity.QuestionType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class QuestionServiceTest {

    @Mock
    private QuestionRepository questionRepository;

    @Mock
    private CourseRepository courseRepository;

    @InjectMocks
    private QuestionService questionService;

    private QuestionDTO questionDTO;
    private Question question;
    private Course course;

    @BeforeEach
    void setUp() {
        course = new Course();
        course.setId(1L);

        QuestionOptionDTO optionDTO = new QuestionOptionDTO("Option 1");
        questionDTO = new QuestionDTO();
        questionDTO.setId(1L);
        questionDTO.setContent("Test Question");
        questionDTO.setType(QuestionType.MCQ);
        questionDTO.setCorrectAnswer("Option 1");
        questionDTO.setCourseId(1L);
        questionDTO.setOptions(Arrays.asList(optionDTO));

        question = new Question();
        question.setId(1L);
        question.setContent("Test Question");
        question.setType(QuestionType.MCQ);
        question.setCorrectAnswer("Option 1");
        question.setCourse(course);
    }

    @Test
    void createQuestion_Success() {
        when(courseRepository.findById(1L)).thenReturn(Optional.of(course));
        when(questionRepository.save(any(Question.class))).thenReturn(question);

        QuestionDTO result = questionService.createQuestion(questionDTO);

        assertNotNull(result);
        assertEquals(questionDTO.getContent(), result.getContent());
        assertEquals(questionDTO.getType(), result.getType());
        verify(questionRepository).save(any(Question.class));
    }

    @Test
    void createQuestion_CourseNotFound() {
        when(courseRepository.findById(1L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> questionService.createQuestion(questionDTO));
        verify(questionRepository, never()).save(any(Question.class));
    }

    @Test
    void getAllQuestions_Success() {
        List<Question> questions = Arrays.asList(question);
        when(questionRepository.findAll()).thenReturn(questions);

        List<QuestionDTO> result = questionService.getAllQuestions();

        assertNotNull(result);
        assertFalse(result.isEmpty());
        assertEquals(1, result.size());
        assertEquals(question.getContent(), result.get(0).getContent());
    }

    @Test
    void getQuestionById_Success() {
        when(questionRepository.findById(1L)).thenReturn(Optional.of(question));

        QuestionDTO result = questionService.getQuestionById(1L);

        assertNotNull(result);
        assertEquals(question.getContent(), result.getContent());
    }

    @Test
    void getQuestionById_NotFound() {
        when(questionRepository.findById(1L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> questionService.getQuestionById(1L));
    }

    @Test
    void deleteQuestion_Success() {
        when(questionRepository.existsById(1L)).thenReturn(true);

        assertDoesNotThrow(() -> questionService.deleteQuestion(1L));
        verify(questionRepository).deleteById(1L);
    }

    @Test
    void deleteQuestion_NotFound() {
        when(questionRepository.existsById(1L)).thenReturn(false);

        assertThrows(RuntimeException.class, () -> questionService.deleteQuestion(1L));
        verify(questionRepository, never()).deleteById(any());
    }

    @Test
    void updateQuestion_Success() {
        when(questionRepository.findById(1L)).thenReturn(Optional.of(question));
        when(courseRepository.findById(1L)).thenReturn(Optional.of(course));
        when(questionRepository.save(any(Question.class))).thenReturn(question);

        QuestionDTO result = questionService.updateQuestion(1L, questionDTO);

        assertNotNull(result);
        assertEquals(questionDTO.getContent(), result.getContent());
        verify(questionRepository).save(any(Question.class));
    }

    @Test
    void getQuestionsByCourseId_Success() {
        course.setQuestionsBank(Arrays.asList(question));
        when(courseRepository.findById(1L)).thenReturn(Optional.of(course));

        List<QuestionDTO> result = questionService.getQuestionsByCourseId(1L);

        assertNotNull(result);
        assertFalse(result.isEmpty());
        assertEquals(1, result.size());
        assertEquals(question.getContent(), result.get(0).getContent());
    }

    @Test
    void getQuestionsByCourseId_CourseNotFound() {
        when(courseRepository.findById(1L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> questionService.getQuestionsByCourseId(1L));
    }

    @Test
    void addQuestionsToCourse_Success() {
        when(courseRepository.findById(1L)).thenReturn(Optional.of(course));
        when(courseRepository.save(any(Course.class))).thenReturn(course);

        List<QuestionDTO> questionDTOs = Arrays.asList(questionDTO);

        assertDoesNotThrow(() -> questionService.addQuestionsToCourse(1L, questionDTOs));
        verify(courseRepository).save(any(Course.class));
    }

    @Test
    void addQuestionsToCourse_CourseNotFound() {
        when(courseRepository.findById(1L)).thenReturn(Optional.empty());

        List<QuestionDTO> questionDTOs = Arrays.asList(questionDTO);

        assertThrows(RuntimeException.class,
                () -> questionService.addQuestionsToCourse(1L, questionDTOs));
        verify(courseRepository, never()).save(any(Course.class));
    }
}