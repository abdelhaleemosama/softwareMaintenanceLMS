package net.java.lms_backend.dto;

import net.java.lms_backend.entity.QuestionType;
import java.util.List;

public class QuestionDTO {
    private Long id;
    private String content;
    private String correctAnswer;
    private List<QuestionOptionDTO> options;
    private Long courseId;
    private QuestionType type;

    public QuestionDTO() {}

    public QuestionDTO(Long id, String content, String correctAnswer, List<QuestionOptionDTO> options, Long courseId, QuestionType type) {
        this.id = id;
        this.content = content;
        this.correctAnswer = correctAnswer;
        this.options = options;
        this.courseId = courseId;
        this.type = type;
    }

    // Getters and setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public String getCorrectAnswer() {
        return correctAnswer;
    }

    public void setCorrectAnswer(String correctAnswer) {
        this.correctAnswer = correctAnswer;
    }

    public List<QuestionOptionDTO> getOptions() {
        return options;
    }

    public void setOptions(List<QuestionOptionDTO> options) {
        this.options = options;
    }

    public Long getCourseId() {
        return courseId;
    }

    public void setCourseId(Long courseId) {
        this.courseId = courseId;
    }

    public QuestionType getType() {
        return type;
    }

    public void setType(QuestionType type) {
        this.type = type;
    }
}