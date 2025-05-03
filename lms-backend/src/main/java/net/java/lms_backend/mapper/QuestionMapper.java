package net.java.lms_backend.mapper;

import net.java.lms_backend.dto.QuestionDTO;
import net.java.lms_backend.dto.QuestionOptionDTO;
import net.java.lms_backend.entity.Course;
import net.java.lms_backend.entity.Question;
import net.java.lms_backend.entity.QuestionOption;

import java.util.List;
import java.util.stream.Collectors;

public class QuestionMapper {

    public static QuestionDTO mapToQuestionDTO(Question question) {
        List<QuestionOptionDTO> options = question.getOptions().stream()
                .map(option -> new QuestionOptionDTO(option.getOptionContent()))
                .collect(Collectors.toList());
        return new QuestionDTO(
                question.getId(),
                question.getContent(),
                question.getCorrectAnswer(),
                options,
                question.getCourse() != null ? question.getCourse().getId() : null,
                question.getType()
        );
    }

    public static Question mapToQuestion(QuestionDTO questionDTO, Course course) {
        Question question = new Question();
        question.setContent(questionDTO.getContent());
        question.setCorrectAnswer(questionDTO.getCorrectAnswer());
        question.setType(questionDTO.getType());
        question.setCourse(course);

        List<QuestionOption> options = questionDTO.getOptions().stream()
                .map(dto -> {
                    QuestionOption option = new QuestionOption();
                    option.setOptionContent(dto.getOptionContent());
                    option.setQuestion(question); // Set the question in the option
                    return option;
                }).collect(Collectors.toList());

        question.setOptions(options);
        return question;
    }
}