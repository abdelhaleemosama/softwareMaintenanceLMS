package net.java.lms_backend.Repositrory;

import net.java.lms_backend.entity.Instructor;
import net.java.lms_backend.entity.Lesson;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LessonRepositery extends JpaRepository<Lesson, Long> {
}
