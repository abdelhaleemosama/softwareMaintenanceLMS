package net.java.lms_backend.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Enrollmentdto {
    private Long courseId;
    private Long studentId;

    public Long getStudentId() {
        return studentId;
    }


}
