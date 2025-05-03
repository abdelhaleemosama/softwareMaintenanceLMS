package net.java.lms_backend.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
public class AssignmentDTO {
    private Long id;
    private String title;
    private String dueDate;
    private Long courseId;
    private List<SubmissionDTO> submissions;

    public AssignmentDTO(String title, String dueDate, long courseId) {
        this.title = title;
        this.dueDate = dueDate;
        this.courseId = courseId;
    }

    public AssignmentDTO() {}
    public String getTitle() {
        return title;
    }

    public String getDueDate() {
        return dueDate;
    }

    public Long getCourseId() {
        return courseId;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public void setSubmissions(List<SubmissionDTO> submissions) {
        this.submissions = submissions;
    }

    public void setCourseId(Long courseId) {
        this.courseId = courseId;
    }

    public void setDueDate(String dueDate) {
        this.dueDate = dueDate;
    }

    public void setTitle(String title) {
        this.title = title;
    }

}
