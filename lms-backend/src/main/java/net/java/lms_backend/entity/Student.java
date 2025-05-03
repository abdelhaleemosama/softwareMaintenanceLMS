package net.java.lms_backend.entity;

import jakarta.persistence.*;

import java.util.List;

@Entity
public class Student extends User{
    @OneToMany(mappedBy = "student", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Enrollment> enrollments;

    @OneToMany(mappedBy = "student", cascade = CascadeType.ALL)
    private List<QuizAttempt> quizAttempts;

    @OneToMany(mappedBy = "student", cascade = CascadeType.ALL)
    private List<Submission> submissions;

    public Student(User user) {
        super(Role.STUDENT,user);
    }

    public Student()
    {
        super(Role.STUDENT,new User());
    }



}
