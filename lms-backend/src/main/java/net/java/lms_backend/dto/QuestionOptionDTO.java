package net.java.lms_backend.dto;

public class QuestionOptionDTO {
    private String optionContent;

    public QuestionOptionDTO() {}

    public QuestionOptionDTO(String optionContent) {
        this.optionContent = optionContent;
    }

    // Getters and setters
    public String getOptionContent() {
        return optionContent;
    }

    public void setOptionContent(String optionContent) {
        this.optionContent = optionContent;
    }
}