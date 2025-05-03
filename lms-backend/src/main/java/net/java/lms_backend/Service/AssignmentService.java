package net.java.lms_backend.Service;

import net.java.lms_backend.Repositrory.AssignmentRepository;
import net.java.lms_backend.Repositrory.CourseRepository;
import net.java.lms_backend.dto.AssignmentDTO;
import net.java.lms_backend.entity.Assignment;
import net.java.lms_backend.mapper.AssignmentMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class AssignmentService {


    @Autowired
    private AssignmentRepository assignmentRepository;

    @Autowired
    private CourseRepository courseRepository;

    @Autowired
    private AssignmentMapper assignmentMapper;

    // Create a new assignment
    public AssignmentDTO createAssignment(AssignmentDTO dto) {
        Assignment assignment = assignmentMapper.toEntity(dto);
        Assignment savedAssignment = assignmentRepository.save(assignment);
        return assignmentMapper.toDTO(savedAssignment);
    }

    // Get an assignment by ID
    public AssignmentDTO getAssignmentById(Long id) {
        Assignment assignment = assignmentRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Assignment not found with id: " + id));
        return assignmentMapper.toDTO(assignment);
    }

    // Get all assignments
    public List<AssignmentDTO> getAllAssignments() {
        return assignmentRepository.findAll().stream()
                .map(assignmentMapper::toDTO)
                .collect(Collectors.toList());
    }

    // Update an assignment by ID
    public AssignmentDTO updateAssignment(Long id, AssignmentDTO dto) {
        Assignment assignment = assignmentRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Assignment not found with id: " + id));

        // Update assignment properties
        assignment.setTitle(dto.getTitle());
        assignment.setDueDate(java.time.LocalDate.parse(dto.getDueDate()));
        if (dto.getCourseId() != null) {
            assignment.setCourse(courseRepository.findById(dto.getCourseId())
                    .orElseThrow(() -> new IllegalArgumentException("Invalid course ID: " + dto.getCourseId())));
        }

        Assignment updatedAssignment = assignmentRepository.save(assignment);
        return assignmentMapper.toDTO(updatedAssignment);
    }

    // Delete an assignment by ID
    public void deleteAssignment(Long id) {
        if (!assignmentRepository.existsById(id)) {
            throw new IllegalArgumentException("Assignment not found with id: " + id);
        }
        assignmentRepository.deleteById(id);
    }
}
