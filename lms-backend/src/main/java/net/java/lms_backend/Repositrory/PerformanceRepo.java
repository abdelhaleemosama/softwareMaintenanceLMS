package net.java.lms_backend.Repositrory;

import net.java.lms_backend.entity.Attendance;
import net.java.lms_backend.entity.Course;
import net.java.lms_backend.entity.Performance;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PerformanceRepo extends JpaRepository<Performance, Long> {
   List<Performance> findByCourseId(Long courseId) ;
    Performance findByStudentIdAndCourseId(Long StudentId, Long CourseId);
}
