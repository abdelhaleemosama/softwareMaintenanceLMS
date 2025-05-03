package net.java.lms_backend.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter

public class PerformanceDto {
        private Long studentId;
        private Long courseId;
        private int totalLessonsAttended;
        private int score;
        private int totalLessons;

        public PerformanceDto(long id, int i) {
                this.studentId=id;
                this.totalLessons=i;
        }
        public PerformanceDto(){

        }

        public Long getStudentId() {
                return studentId;
        }

        public void setCourseId(Long courseId) {
                this.courseId = courseId;
        }

        public void setScore(int score) {
                this.score = score;
        }

        public void setStudentId(Long studentId) {
                this.studentId = studentId;
        }

        public void setTotalLessonsAttended(int totalLessonsAttended) {
                this.totalLessonsAttended = totalLessonsAttended;
        }

        public void setTotalLessons(int totalLessons) {
                this.totalLessons = totalLessons;
        }
}
