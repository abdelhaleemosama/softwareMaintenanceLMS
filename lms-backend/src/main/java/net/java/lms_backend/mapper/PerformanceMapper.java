package net.java.lms_backend.mapper;

import net.java.lms_backend.dto.PerformanceDto;
import net.java.lms_backend.entity.Performance;

public class PerformanceMapper {
        public static PerformanceDto mapToPerformanceDTO(Performance performance) {
            if (performance == null) {
                return null;
            }
            PerformanceDto dto = new PerformanceDto();
            dto.setTotalLessonsAttended(performance.getTotalLessonsAttended());
            dto.setScore(performance.getScore());
            dto.setCourseId(performance.getCourse().getId());
            dto.setStudentId(performance.getStudent().getId());
            dto.setTotalLessons(performance.getTotalLessons());
            return dto;
    }
}
