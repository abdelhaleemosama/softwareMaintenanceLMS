package net.java.lms_backend.entity;

import jakarta.persistence.*;

@Entity
public class Attendance {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "lesson_id")
    private Lesson lesson;

    private String otp;
    private boolean active;


    @ManyToOne
    @JoinColumn(name = "student_id")
    private Student student;


    public void setStudent(Student student) {
        this.student = student;
    }

    public Student getStudent() {
        return student;
    }
    public void setLesson(Lesson lesson) {
        this.lesson=lesson;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public void setOtp(String otp) {
        this.otp = otp;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public boolean isActive() {
        return active;
    }

    public Lesson getLesson() {
        return lesson;
    }

    public String getOtp() {
        return otp;
    }


}
