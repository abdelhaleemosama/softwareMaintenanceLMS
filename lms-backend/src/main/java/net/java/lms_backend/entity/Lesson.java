package net.java.lms_backend.entity;

import jakarta.persistence.*;

import java.util.ArrayList;
import  net.java.lms_backend.entity.Attendance;
import java.util.List;

@Entity
public class Lesson {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false)
    private String title;
    @Column(length =1000)
    private String content;
    @ManyToOne
    @JoinColumn(name = "course_id")
    private Course course;

    @OneToMany(mappedBy = "lesson")
    private List<Attendance> attendances = new ArrayList<>();


    public void setCourse(Course course) {
        this.course=course;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public Long getId() {
        return id;
    }

    public void setId(long l) {
        this.id=id;
    }

    public Course getCourse() {
        return course;
    }

    public String getTitle() {
        return title;
    }
}