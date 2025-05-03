package net.java.lms_backend.Service;

import net.java.lms_backend.Repositrory.CourseRepository;
import net.java.lms_backend.Repositrory.QuestionRepository;

import net.java.lms_backend.dto.QuestionDTO;
import net.java.lms_backend.entity.Course;
import net.java.lms_backend.entity.Question;
import net.java.lms_backend.entity.QuestionOption;
import net.java.lms_backend.mapper.QuestionMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class QuestionService {
    private final QuestionRepository questionRepository;
    private final CourseRepository courseRepository;

    public QuestionService(QuestionRepository questionRepository, CourseRepository courseRepository) {
        this.questionRepository = questionRepository;
        this.courseRepository = courseRepository;
    }

    @Transactional
    public QuestionDTO createQuestion(QuestionDTO questionDTO) {
        Course course = courseRepository.findById(questionDTO.getCourseId())
                .orElseThrow(() -> new RuntimeException("Course not found with ID: " + questionDTO.getCourseId()));

        Question question = QuestionMapper.mapToQuestion(questionDTO, course);
        question = questionRepository.save(question);

        return QuestionMapper.mapToQuestionDTO(question);
    }

    public List<QuestionDTO> getAllQuestions() {
        return questionRepository.findAll()
                .stream()
                .map(QuestionMapper::mapToQuestionDTO)
                .collect(Collectors.toList());
    }

    public QuestionDTO getQuestionById(Long id) {
        Question question = questionRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Question not found with ID: " + id));
        return QuestionMapper.mapToQuestionDTO(question);
    }

    public void deleteQuestion(Long id) {
        if (!questionRepository.existsById(id)) {
            throw new RuntimeException("Question not found with ID: " + id);
        }
        questionRepository.deleteById(id);
    }

    @Transactional
    public QuestionDTO updateQuestion(Long id, QuestionDTO questionDTO) {
        Question existingQuestion = questionRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Question not found with ID: " + id));

        Course course = courseRepository.findById(questionDTO.getCourseId())
                .orElseThrow(() -> new RuntimeException("Course not found with ID: " + questionDTO.getCourseId()));

        existingQuestion.setContent(questionDTO.getContent());
        existingQuestion.setType(questionDTO.getType());
        existingQuestion.setOptions(questionDTO.getOptions().stream()
                .map(dto -> {
                    QuestionOption option = new QuestionOption();
                    option.setOptionContent(dto.getOptionContent());
                    option.setQuestion(existingQuestion);
                    return option;
                }).collect(Collectors.toList()));
        existingQuestion.setCorrectAnswer(questionDTO.getCorrectAnswer());
        existingQuestion.setCourse(course);

        Question updatedQuestion = questionRepository.save(existingQuestion);
        return QuestionMapper.mapToQuestionDTO(updatedQuestion);
    }

    @Transactional
    public void addQuestionsToCourse(Long courseId, List<QuestionDTO> questionDTOs) {
        Course course = courseRepository.findById(courseId)
                .orElseThrow(() -> new RuntimeException("Course not found with id: " + courseId));

        List<Question> questions = questionDTOs.stream()
                .map(questionDTO -> {
                    Question question = QuestionMapper.mapToQuestion(questionDTO, course);
                    course.addQuestion(question); // Ensure bidirectional relationship is maintained
                    return question;
                })
                .collect(Collectors.toList());

        course.getQuestionsBank().addAll(questions); // Add all questions to the course's question bank
        courseRepository.save(course);
    }

    public List<QuestionDTO> getQuestionsByCourseId(Long courseId) {
        Course course = courseRepository.findById(courseId)
                .orElseThrow(() -> new RuntimeException("Course not found with id: " + courseId));

        List<Question> questions = course.getQuestionsBank();

        return questions.stream()
                .map(QuestionMapper::mapToQuestionDTO)
                .collect(Collectors.toList());
    }
}