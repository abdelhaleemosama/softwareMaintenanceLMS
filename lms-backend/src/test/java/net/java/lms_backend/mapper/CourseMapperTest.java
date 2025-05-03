package net.java.lms_backend.mapper;

import net.java.lms_backend.dto.Coursedto;
import net.java.lms_backend.entity.Course;
import net.java.lms_backend.entity.Instructor;
import net.java.lms_backend.entity.MediaFiles;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CourseMapperTest {
    private CourseMapper courseMapper;
    @BeforeEach
    void setUp(){
        courseMapper=new CourseMapper();

    }

    @Test
    void mapToCoursedto() {
        MediaFiles mediaFile1 = new MediaFiles(1L, "file1.pdf");
        MediaFiles mediaFile2 = new MediaFiles(2L, "file2.doc");
        Instructor instructor = new Instructor();
        instructor.setId(1L);
        Course course = new Course();
        course.setId(1L);
        course.setTitle("Advanced SW");
        course.setDescription("course on SW");
        course.setDuration("6 weeks");
        course.setMediaFiles(List.of(mediaFile1, mediaFile2));
        course.setInstructor(instructor);
        Coursedto coursedto=CourseMapper.mapToCoursedto(course);
        assertEquals(course.getId(), coursedto.getId());
        assertEquals(course.getTitle(), coursedto.getTitle());
        assertEquals(course.getDescription(), coursedto.getDescription());
        assertEquals(course.getDuration(), coursedto.getDuration());
        assertEquals(course.getInstructor().getId(), coursedto.getInstructorId());
        assertEquals(course.getMediaFiles().size(), coursedto.getMediaFiles().size());
        assertEquals(course.getMediaFiles().get(0).getFileName(), coursedto.getMediaFiles().get(0).getFileName());
        assertEquals(course.getMediaFiles().get(1).getFileName(), coursedto.getMediaFiles().get(1).getFileName());


    }

    @Test
    void maptoCourse() {
        MediaFiles mediaFile1 = new MediaFiles(1L, "file1.pdf");
        MediaFiles mediaFile2 = new MediaFiles(2L, "file2.doc");
        Instructor instructor = new Instructor();
        instructor.setId(1L);
        Coursedto coursedto=new Coursedto(
                1L,
                "Advanced SW",
                "course on Sw",
                "6 weeks",
                List.of(mediaFile1,mediaFile2),
                instructor.getId()
        );
        Course course=CourseMapper.maptoCourse(coursedto);
        assertEquals(coursedto.getId(),course.getId());
        assertEquals(coursedto.getTitle(), course.getTitle());
        assertEquals(coursedto.getDescription(), course.getDescription());
        assertEquals(coursedto.getDuration(), course.getDuration());
        assertEquals(coursedto.getMediaFiles().size(), course.getMediaFiles().size());
    }
    @Test
    void ThrowIfDTOisNull(){
        var exp=assertThrows(NullPointerException.class,()->CourseMapper.maptoCourse(null));
        assertEquals("The CourseDTO Should not be null",exp.getMessage());

    }
}
