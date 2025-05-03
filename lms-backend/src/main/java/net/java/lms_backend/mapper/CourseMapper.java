package net.java.lms_backend.mapper;

import net.java.lms_backend.dto.Coursedto;
import net.java.lms_backend.entity.*;

import java.util.List;
import java.util.stream.Collectors;

public class CourseMapper {
    public static Coursedto mapToCoursedto(Course course){
        return new Coursedto(
                course.getId(),
                course.getTitle(),
                course.getDescription(),
                course.getDuration(),
                course.getMediaFiles().stream()
                        .map(mediaFile -> new MediaFiles(mediaFile.getId(), mediaFile.getFileName()))
                        .collect(Collectors.toList()),
               // course.getUser().getId(),
                course.getInstructor().getId()
        );


    }
    public static Course maptoCourse(Coursedto coursedto) {
        if(coursedto==null){
            throw new NullPointerException("The CourseDTO Should not be null");
        }
        Course course = new Course();
        course.setId(coursedto.getId());
        course.setTitle(coursedto.getTitle());
        course.setDescription(coursedto.getDescription());
        course.setDuration(coursedto.getDuration());
        course.setMediaFiles(coursedto.getMediaFiles());
//        course.setUser(coursedto.getUser());
        course.setInstructor(coursedto.getInstructor());
        return course;
    }

}