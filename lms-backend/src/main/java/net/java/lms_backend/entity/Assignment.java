package net.java.lms_backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Entity
public class Assignment extends Assessment {
    @OneToMany(mappedBy = "assignment", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Submission> submissions = new ArrayList<>();



    public String getTitle() {
        return super.getTitle();
    }



    public void setTitle(String title) {
        super.setTitle(title);
    }

    public LocalDate getDueDate() {
        return super.getDueDate();
    }

    public void setDueDate(LocalDate dueDate) {
        super.setDueDate(dueDate);
    }

    public Course getCourse() {
        return super.getCourse();
    }

    public void setCourse(Course course) {
        super.setCourse(course);
    }


}
