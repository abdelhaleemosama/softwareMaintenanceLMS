package net.java.lms_backend.dto;

public class QuizDTO {
    private Long numOfMCQ;
    private Long numOfTrueFalse;
    private Long numOfShortAnswer;

    public Long getNumOfMCQ() {
        return numOfMCQ;
    }

    public void setNumOfMCQ(Long numOfMCQ) {
        this.numOfMCQ = numOfMCQ;
    }

    public Long getNumOfTrueFalse() {
        return numOfTrueFalse;
    }

    public void setNumOfTrueFalse(Long numOfTrueFalse) {
        this.numOfTrueFalse = numOfTrueFalse;
    }

    public Long getNumOfShortAnswer() {
        return numOfShortAnswer;
    }

    public void setNumOfShortAnswer(Long numOfShortAnswer) {
        this.numOfShortAnswer = numOfShortAnswer;
    }
}
