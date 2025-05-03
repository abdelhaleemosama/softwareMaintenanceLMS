package net.java.lms_backend.Service;

import net.java.lms_backend.Repositrory.*;
import net.java.lms_backend.dto.Coursedto;
import net.java.lms_backend.dto.StudentDTO;
import net.java.lms_backend.entity.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.*;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;
import java.util.Optional;


class CourseServiceTest {
    @InjectMocks
    private CourseService courseService;
    @Mock
    private CourseRepository courseRepo;
    @Mock
    private UserRepository userRepo;
    @Mock
    private InstructorRepository instructorRepo;
    @Mock
    private LessonRepositery lessonRepo;
    @Mock
    private StudentRepository studentRepository;
    @Mock
    private EnrollmentRepo enrollmentRepo;
    @Mock
    private AttendanceRepo attendanceRepo;
    @Mock
    private PerformanceRepo performanceRepo;
    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void createCourse() {
        MediaFiles mediaFile1 = new MediaFiles(1L, "file1.pdf");
        MediaFiles mediaFile2 = new MediaFiles(2L, "file2.doc");
        Instructor instructor = new Instructor();
        instructor.setId(1L);
        Coursedto coursedto=new Coursedto(
                null,
                "Advanced SW",
                "course on Sw",
                "6 weeks",
                List.of(mediaFile1,mediaFile2),
                instructor.getId()
        );

        when(instructorRepo.findById(1L)).thenReturn(Optional.of(instructor));

        Course savedCourse = new Course();
        savedCourse.setId(1L);
        savedCourse.setTitle(coursedto.getTitle());
        savedCourse.setDescription(coursedto.getDescription());
        savedCourse.setDuration(coursedto.getDuration());
        savedCourse.setMediaFiles(coursedto.getMediaFiles());
        savedCourse.setInstructor(instructor);

        when(courseRepo.save(any(Course.class))).thenReturn(savedCourse);

        Coursedto result = courseService.CreateCourse(coursedto);
        assertEquals(1L, result.getId());
        assertEquals(coursedto.getTitle(), result.getTitle());
        assertEquals(coursedto.getDescription(), result.getDescription());
        assertEquals(coursedto.getDuration(), result.getDuration());
        assertEquals(coursedto.getMediaFiles().get(0).getFileName(), result.getMediaFiles().get(0).getFileName());
        assertEquals(coursedto.getMediaFiles().get(1).getFileName(), result.getMediaFiles().get(1).getFileName());
        assertEquals(coursedto.getInstructorId(), result.getInstructorId());

        verify(instructorRepo, times(1)).findById(1L);
        verify(courseRepo, times(1)).save(any(Course.class));

    }

    @Test
    void viewAllCourse() {
        List<Course> courses=new ArrayList<>();
        MediaFiles mediaFile1 = new MediaFiles(1L, "file1.pdf");
        MediaFiles mediaFile2 = new MediaFiles(2L, "file2.doc");
        Instructor instructor = new Instructor();
        instructor.setId(1L);
        courses.add(new Course(
                1L,
                "Advanced SW",
                "course on Sw",
                "6 weeks",
                List.of(mediaFile1,mediaFile2),
                instructor

        ));
        when(courseRepo.findAll()).thenReturn(courses);
        List<Coursedto> result = courseService.ViewAllCourse();
        assertEquals(courses.size(), result.size());
        assertEquals(courses.get(0).getTitle(), result.get(0).getTitle());
        assertEquals(courses.get(0).getDescription(), result.get(0).getDescription());
        assertEquals(courses.get(0).getDuration(), result.get(0).getDuration());
        assertEquals(courses.get(0).getMediaFiles().get(0).getFileName(), result.get(0).getMediaFiles().get(0).getFileName());
        assertEquals(courses.get(0).getMediaFiles().get(1).getFileName(), result.get(0).getMediaFiles().get(1).getFileName());
        verify(courseRepo, times(1)).findAll();


    }

    @Test
    void getCoursesByInstructor() {
        Long instructorId = 1L;
        MediaFiles mediaFile1 = new MediaFiles(1L, "file1.pdf");
        MediaFiles mediaFile2 = new MediaFiles(2L, "file2.doc");
        Instructor instructor = new Instructor();
        instructor.setId(1L);
        List<Course> courses=new ArrayList<>();
        courses.add(new Course(
                1L,
                "Advanced SW",
                "course on Sw",
                "6 weeks",
                List.of(mediaFile1,mediaFile2),
                instructor

        ));
        when(courseRepo.findByInstructorId(instructorId)).thenReturn(courses);
        List<Coursedto> result = courseService.getCoursesByInstructor(instructorId);
        assertEquals(courses.size(), result.size());
        assertEquals(courses.get(0).getTitle(), result.get(0).getTitle());
        assertEquals(courses.get(0).getDescription(), result.get(0).getDescription());
        assertEquals(courses.get(0).getDuration(), result.get(0).getDuration());
        assertEquals(courses.get(0).getMediaFiles().get(0).getFileName(), result.get(0).getMediaFiles().get(0).getFileName());
        assertEquals(courses.get(0).getMediaFiles().get(1).getFileName(), result.get(0).getMediaFiles().get(1).getFileName());
        verify(courseRepo, times(1)).findByInstructorId(instructorId);


    }
    @Test
    void getCourseById() {
        Long courseId=1L;
        MediaFiles mediaFile1 = new MediaFiles(1L, "file1.pdf");
        MediaFiles mediaFile2 = new MediaFiles(2L, "file2.doc");
        Instructor instructor = new Instructor();
        instructor.setId(1L);
        Course course=new Course(
                1L,
                "Advanced SW",
                "course on Sw",
                "6 weeks",
                List.of(mediaFile1,mediaFile2),
                instructor
        );
        when(courseRepo.findById(courseId)).thenReturn(Optional.of(course));
        Coursedto result = courseService.getCourseById(1L);
        assertEquals(course.getTitle(), result.getTitle());
        assertEquals(course.getDescription(), result.getDescription());
        assertEquals(course.getDuration(), result.getDuration());
        assertEquals(course.getMediaFiles().get(0).getFileName(), result.getMediaFiles().get(0).getFileName());
        assertEquals(course.getMediaFiles().get(1).getFileName(), result.getMediaFiles().get(1).getFileName());
        verify(courseRepo, times(1)).findById(1L);


    }
    @Test
    void deleteCourse() {
        Long courseId = 1L;

        doNothing().when(courseRepo).deleteById(courseId);

        courseService.deleteCourse(courseId);

        verify(courseRepo, times(1)).deleteById(courseId);
    }

    @Test
    public void testAddLessonToCourse() {
        Long courseId = 1L;
        Lesson lesson = new Lesson();
        lesson.setTitle("Lesson 1");
        lesson.setContent("Content");

        Course course = new Course();
        course.setId(courseId);
        course.setTitle("Advanced SW");

        when(courseRepo.findById(courseId)).thenReturn(Optional.of(course));
        when(lessonRepo.save(any(Lesson.class))).thenAnswer(invocation -> invocation.getArgument(0));

        Lesson addedLesson = courseService.addLessonToCourse(courseId, lesson);
        assertEquals(lesson.getTitle(), addedLesson.getTitle());
        assertEquals(course, addedLesson.getCourse());
        verify(courseRepo, times(1)).findById(courseId);
        verify(lessonRepo, times(1)).save(lesson);
    }

    @Test
    public void testUploadMediaFiles() throws IOException {
        Long courseId = 1L;
        List<MultipartFile> files = new ArrayList<>();
        MultipartFile file = Mockito.mock(MultipartFile.class);
        when(file.getOriginalFilename()).thenReturn("File1.txt");
        files.add(file);
        Course course = new Course();
        course.setId(courseId);
        course.setTitle("Advanced SW");
        when(courseRepo.findById(courseId)).thenReturn(Optional.of(course));
        when(courseRepo.save(any(Course.class))).thenAnswer(invocation -> invocation.getArgument(0));


        courseService.uploadMediaFiles(courseId, files);

        assertEquals(files.size(), course.getMediaFiles().size());
        assertEquals(files.get(0).getOriginalFilename(), course.getMediaFiles().get(0).getFileName());
        verify(courseRepo, times(1)).save(course);
    }

    @Test
    void enrollStudentInCourse() {
        Long courseId = 1L;
        Long studentId = 2L;


        Course course = new Course();
        course.setId(courseId);
        when(courseRepo.findById(courseId)).thenReturn(Optional.of(course));

        Student student = new Student();
        student.setId(studentId);
        when(studentRepository.findById(studentId)).thenReturn(Optional.of(student));

        courseService.enrollStudentInCourse(courseId, studentId);

        verify(enrollmentRepo, times(1)).save(any(Enrollment.class));

        verify(performanceRepo, times(1)).save(any(Performance.class));
    }


    @Test
    void getEnrolledStudents() {
        Long courseId = 1L;
        Student student1 = new Student();
        student1.setId(1L);
        student1.setUsername("Student 1");

        Student student2 = new Student();
        student2.setId(2L);
        student2.setUsername("Student 2");
        Enrollment enrollment1 = new Enrollment();
        enrollment1.setStudent(student1);

        Enrollment enrollment2 = new Enrollment();
        enrollment2.setStudent(student2);

        List<Enrollment> Enrollments = List.of(enrollment1, enrollment2);

        when(enrollmentRepo.findByCourseId(courseId)).thenReturn(Enrollments);

        List<StudentDTO> result = courseService.getEnrolledStudents(courseId);

        assertEquals(Enrollments.size(), result.size());
        assertEquals(Enrollments.get(0).getStudent().getId(), result.get(0).getId());
        assertEquals(Enrollments.get(1).getStudent().getId(), result.get(1).getId());

        verify(enrollmentRepo, times(1)).findByCourseId(courseId);
    }


    @Test
    void generateOtp() {
        Long lessonId = 1L;
        Lesson lesson = new Lesson();
        lesson.setId(lessonId);
        when(lessonRepo.findById(lessonId)).thenReturn(Optional.of(lesson));

        String otp = courseService.generateOtp(lessonId);

        assertNotNull(otp);
        assertFalse(otp.isEmpty());
        verify(attendanceRepo, times(1)).save(any(Attendance.class));

    }

    @Test
    void validateOtp() {
        Long lessonId = 1L;
        String otp = "10098";
        Long studentId = 1L;
        Course course = new Course();
        course.setId(1L);
        Lesson lesson = new Lesson();
        lesson.setCourse(course);

        Attendance attendance = new Attendance();
        attendance.setOtp(otp);
        attendance.setActive(true);
        attendance.setLesson(lesson);

        when(attendanceRepo.findByLessonIdAndOtp(lessonId, otp)).thenReturn(attendance);

        Student student = new Student();
        student.setId(studentId);
        when(studentRepository.findById(studentId)).thenReturn(Optional.of(student));

        Performance performance = new Performance();
        performance.setTotalLessonsAttended(0);
        when(performanceRepo.findByStudentIdAndCourseId(studentId, course.getId())).thenReturn(performance);

        boolean result = courseService.validateOtp(lessonId, otp, studentId);


        assertTrue(result);
        assertFalse(attendance.isActive());
        assertEquals(student, attendance.getStudent());
        assertEquals(1, performance.getTotalLessonsAttended());


        verify(attendanceRepo, times(1)).save(attendance);
        verify(studentRepository, times(1)).findById(studentId);
        verify(performanceRepo, times(1)).save(performance);
    }



}
