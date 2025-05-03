package net.java.lms_backend.Repositrory;

import net.java.lms_backend.dto.Coursedto;
import net.java.lms_backend.entity.Course;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CourseRepository extends JpaRepository<Course,Long> {
    List<Course> findByInstructorId(Long instructorId);

}
