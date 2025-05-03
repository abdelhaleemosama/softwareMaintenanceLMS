package net.java.lms_backend.mapper;

import net.java.lms_backend.Repositrory.CourseRepository;
import net.java.lms_backend.dto.AssignmentDTO;
import net.java.lms_backend.entity.Assignment;
import net.java.lms_backend.entity.Course;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.LocalDate;

@Component
public class AssignmentMapper {
    @Autowired
    private CourseRepository courseRepository; // Repository to fetch Course

    public Assignment toEntity(AssignmentDTO dto) {
        Assignment assignment = new Assignment();
        assignment.setTitle(dto.getTitle());
        assignment.setDueDate(LocalDate.parse(dto.getDueDate()));

        if (dto.getCourseId() != null) {
            Course course = courseRepository.findById(dto.getCourseId())
                    .orElseThrow(() -> new IllegalArgumentException("Invalid course ID: " + dto.getCourseId()));
            assignment.setCourse(course);
        }

        return assignment;
    }

    public AssignmentDTO toDTO(Assignment assignment) {
        AssignmentDTO dto = new AssignmentDTO();
        dto.setId(assignment.getId());
        dto.setTitle(assignment.getTitle());
        dto.setDueDate(assignment.getDueDate().toString());
        if (assignment.getCourse() != null) {
            dto.setCourseId(assignment.getCourse().getId());
        }
        return dto;
    }
}