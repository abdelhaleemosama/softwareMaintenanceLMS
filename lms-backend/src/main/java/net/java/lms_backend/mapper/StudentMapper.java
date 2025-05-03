package net.java.lms_backend.mapper;

import net.java.lms_backend.dto.StudentDTO;
import net.java.lms_backend.entity.Student;

public class StudentMapper {
    public static StudentDTO mapToStudentDTO(Student student) {
        if (student == null) {
            return null;
        }
        return new StudentDTO(student.getId(), student.getUsername(), student.getEmail());
    }

    public static Student mapToStudent(StudentDTO studentDTO) {
        if (studentDTO == null) {
            return null;
        }
        Student student = new Student();
        student.setId(studentDTO.getId());
        student.setUsername(studentDTO.getUsername());
        student.setEmail(studentDTO.getEmail());
        return student;
    }
}
