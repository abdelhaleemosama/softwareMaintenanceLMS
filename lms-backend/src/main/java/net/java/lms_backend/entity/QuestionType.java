package net.java.lms_backend.entity;

public enum QuestionType {
    MCQ,
    TRUE_FALSE,
    SHORT_ANSWER;

    public boolean equalsIgnoreCase(String type) {
        return this.name().equalsIgnoreCase(type);
    }
}
