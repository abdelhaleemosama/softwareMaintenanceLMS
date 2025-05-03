package net.java.lms_backend.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.*;

@Entity
public class MediaFiles {

    @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private long id;
        private String fileName;

        @ManyToOne
        @JoinColumn(name = "course_id")
        private Course course;
        public MediaFiles(){

        }

    public MediaFiles(Long id, String fileName) {
            this.id=id;
            this.fileName=fileName;
    }


    public void setId(long id) {
            this.id = id;
        }

        public String getFileName() {
            return fileName;
        }

        public void setFileName(String fileName) {
            this.fileName = fileName;
        }

        public Course getCourse() {
            return course;
        }

        public void setCourse(Course course) {
            this.course = course;
        }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getId() {
        return id;
    }
}


