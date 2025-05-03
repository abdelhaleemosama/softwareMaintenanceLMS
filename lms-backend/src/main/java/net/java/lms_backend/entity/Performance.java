package net.java.lms_backend.entity;
import jakarta.persistence.*;

@Entity
public class Performance {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long PerformanceId;

    private int score;

    @ManyToOne
    @JoinColumn(name = "student_id")
    private Student student;

    @ManyToOne
    @JoinColumn(name = "course_id")
    private Course course;
    private int totalLessonsAttended;
    private int totalLessons;

    public int getTotalLessonsAttended() {
        return totalLessonsAttended;
    }

    public void setTotalLessonsAttended(int totalClassesAttended) {
        this.totalLessonsAttended = totalClassesAttended;
    }

    public int getScore() {
        return score;
    }

    public void setStudent(Student student) {
        this.student=student;
    }

    public void setScore(int score) {
        this.score = score;
    }

    public void setCourse(Course course) {
        this.course = course;
    }

    public Course getCourse() {
        return course;
    }

    public Student getStudent() {
        return student;
    }

    public void setPerformanceId(long performanceId) {
        PerformanceId = performanceId;
    }

    public int getTotalLessons() {
        return totalLessons;
    }
}
