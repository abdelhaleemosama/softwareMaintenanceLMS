package net.java.lms_backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Entity
public class Course {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }
    public Long getId()
    {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public void setMediaFiles(List<MediaFiles> mediaFiles) {
        this.mediaFiles = mediaFiles;
    }

    public void setDuration(String duration) {
        this.duration = duration;
    }

    public void setQuestionsBank(List<Question> questionsBank) {
        this.questionsBank = questionsBank;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public void setInstructor(Instructor instructor) {
        this.instructor = instructor;
    }

    public void setLessons(List<Lesson> lessons) {
        this.lessons = lessons;
    }

    public String getDescription() {
        return description;
    }

    public String getDuration() {
        return duration;
    }

    public List<MediaFiles> getMediaFiles() {
        return mediaFiles;
    }

    public List<Question> getQuestionsBank() {
        return questionsBank;
    }

    public User getUser() {
        return user;
    }

    public Instructor getInstructor() {
        return instructor;
    }

    public List<Lesson> getLessons() {
        return lessons;
    }

    @Column(nullable = false)
    private String title;
    private String description;
    private String duration;

    @OneToMany(mappedBy = "course", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<MediaFiles> mediaFiles = new ArrayList<>();

    @OneToMany(mappedBy = "course", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Question> questionsBank = new ArrayList<>();

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne
    @JoinColumn(name = "instructor_id", nullable = false)
    private Instructor instructor;

    @OneToMany(mappedBy = "course", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.EAGER)
    private List<Lesson> lessons = new ArrayList<>();

    public Course(long id, String title, String description, String duration, List<MediaFiles> mediaFiles, User user, Instructor instructor) {
        this.id = id;
        this.title = title;
        this.description = description;
        this.duration = duration;
        this.mediaFiles = mediaFiles;
        this.user = user;
        this.instructor = instructor;
    }

    public Course() {
    }

    public void addLesson(Lesson lesson) {
        lessons.add(lesson);
        lesson.setCourse(this);
    }

    public void removeLesson(Lesson lesson) {
        lessons.remove(lesson);
        lesson.setCourse(null);
    }

    public void addMediaFile(MediaFiles mediaFile) {
        mediaFiles.add(mediaFile);
        mediaFile.setCourse(this);
    }

    public void removeMediaFile(MediaFiles mediaFile) {
        mediaFiles.remove(mediaFile);
        mediaFile.setCourse(null);
    }

    public void addQuestion(Question question) {
        questionsBank.add(question);
        question.setCourse(this);
    }
}
