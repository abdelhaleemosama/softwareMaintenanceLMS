package net.java.lms_backend.entity;
import jakarta.persistence.*;

import java.util.List;

@Entity
public class Quiz extends Assessment {

    Long numOfMCQ = 0L;
    Long numOfTrueFalse = 0L;
    Long numOfShortAnswer = 0L;

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


