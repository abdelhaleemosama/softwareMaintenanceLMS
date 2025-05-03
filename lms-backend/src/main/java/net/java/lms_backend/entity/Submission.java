package net.java.lms_backend.entity;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;


import java.time.LocalDateTime;

@Getter
@Setter
@Entity
public class Submission {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    private Assignment assignment;

    @ManyToOne
    private Student student;

    private LocalDateTime submittedAt = LocalDateTime.now();

    private String fileName;



    private Double grade = null; // Grading by instructor
    private String feedback = null;
    public Submission() {}

    public Submission(Assignment assignment, Student student, String fileUrl) {
        this.assignment = assignment;
        this.student = student;
        this.submittedAt = LocalDateTime.now();
        this.fileName = fileUrl;
    }

    public void setId(Long id) {
        this.id = id;
    }


    public void setGrade(Double grade) {
        this.grade = grade;
    }

    public void setAssignment(Assignment assignment) {
        this.assignment = assignment;
    }

    public void setStudent(Student student) {
        this.student = student;
    }

    public void setSubmittedAt(LocalDateTime submittedAt) {
        this.submittedAt = submittedAt;
    }

    public void setFileName(String fileUrl) {
        this.fileName = fileUrl;
    }

    public void setFeedback(String feedback) {
        this.feedback = feedback;
    }


    public long getId() {
        return id;
    }
    public Assignment getAssignment() {
        return assignment;
    }

    public Student getStudent() {
        return student;
    }

    public LocalDateTime getSubmittedAt() {
        return submittedAt;
    }

    public String getFileName() {
        return fileName;
    }

    public Double getGrade() {
        return grade;
    }

    public String getFeedback() {
        return feedback;
    }


}

