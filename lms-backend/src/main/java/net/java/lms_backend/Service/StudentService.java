package net.java.lms_backend.Service;

import lombok.Getter;
import lombok.Setter;
import net.java.lms_backend.Repositrory.*;
import net.java.lms_backend.dto.StudentDTO;
import net.java.lms_backend.entity.Student;
import net.java.lms_backend.mapper.StudentMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;


@Getter
@Setter
@Service
public class StudentService {
    @Autowired
    private StudentRepository studentRepository;
    private final CourseRepository courseRepo;
    private final UserRepository userRepo;
    private final InstructorRepository instructorRepo;
    private final LessonRepositery lessonRepo;
    private final EnrollmentRepo enrollmentRepo;
    private final AttendanceRepo attendanceRepo;

    public StudentService(CourseRepository courseRepo, UserRepository userRepo, InstructorRepository instructorRepo, LessonRepositery lessonRepo, EnrollmentRepo enrollmentRepo, StudentRepository studentRepository, AttendanceRepo attendanceRepo) {
        this.courseRepo = courseRepo;
        this.userRepo = userRepo;
        this.instructorRepo = instructorRepo;
        this.lessonRepo=lessonRepo;
        this.enrollmentRepo=enrollmentRepo;
        this.studentRepository = studentRepository;
        this.attendanceRepo=attendanceRepo;
    }
    

    public List<StudentDTO> getAllStudents() {
        List<Student> students = studentRepository.findAll();
        return students.stream()
                .map(StudentMapper::mapToStudentDTO)
                .collect(Collectors.toList());
    }

    public StudentDTO getStudentById(Long id) {
        return studentRepository.findById(id)
                .map(StudentMapper::mapToStudentDTO)
                .orElse(null);
    }

    public StudentDTO createStudent(StudentDTO studentDTO) {
        Student student = StudentMapper.mapToStudent(studentDTO);
        Student savedStudent = studentRepository.save(student);
        return StudentMapper.mapToStudentDTO(savedStudent);
    }

    public StudentDTO updateStudent(Long id, StudentDTO studentDTO) {
        return studentRepository.findById(id)
                .map(existingStudent -> {
                    existingStudent.setUsername(studentDTO.getUsername());
                    existingStudent.setEmail(studentDTO.getEmail());
                    Student updatedStudent = studentRepository.save(existingStudent);
                    return StudentMapper.mapToStudentDTO(updatedStudent);
                })
                .orElse(null);
    }

    public boolean deleteStudent(Long id) {
        if (studentRepository.existsById(id)) {
            studentRepository.deleteById(id);
            return true;
        }
        return false;
    }
}
