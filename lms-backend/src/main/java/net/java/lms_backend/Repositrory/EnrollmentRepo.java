package net.java.lms_backend.Repositrory;

import net.java.lms_backend.dto.Enrollmentdto;
import net.java.lms_backend.entity.Enrollment;
import net.java.lms_backend.entity.Instructor;
import net.java.lms_backend.entity.Student;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface EnrollmentRepo extends JpaRepository<Enrollment, Long> {
    List<Enrollment> findByCourseId(Long courseId);
}
