package net.java.lms_backend.Service;

import lombok.Getter;
import lombok.Setter;
import net.java.lms_backend.Repositrory.*;
import net.java.lms_backend.dto.*;
import net.java.lms_backend.entity.*;
import net.java.lms_backend.mapper.CourseMapper;
import net.java.lms_backend.mapper.PerformanceMapper;
import net.java.lms_backend.mapper.QuestionMapper;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;
import net.java.lms_backend.mapper.StudentMapper;

@Service
public class CourseService {
    private final CourseRepository courseRepo;
    private final UserRepository userRepo;
    private final InstructorRepository instructorRepo;
    private final LessonRepositery lessonRepo;
    private final StudentRepository studentRepository;
    private final EnrollmentRepo enrollmentRepo;
    private final AttendanceRepo attendanceRepo;
    private final PerformanceRepo performanceRepo;

    public UserRepository getUserRepo() {
        return userRepo;
    }

    public CourseRepository getCourseRepo() {
        return courseRepo;
    }

    public InstructorRepository getInstructorRepo() {
        return instructorRepo;
    }

    public LessonRepositery getLessonRepo() {
        return lessonRepo;
    }

    public EnrollmentRepo getEnrollmentRepo() {
        return enrollmentRepo;
    }

    public StudentRepository getStudentRepository() {
        return studentRepository;
    }

    public AttendanceRepo getAttendanceRepo() {
        return attendanceRepo;
    }

    public PerformanceRepo getPerformanceRepo() {
        return performanceRepo;
    }


    public CourseService(CourseRepository courseRepo, UserRepository userRepo, InstructorRepository instructorRepo, LessonRepositery lessonRepo, EnrollmentRepo enrollmentRepo, StudentRepository studentRepository, AttendanceRepo attendanceRepo, PerformanceRepo performanceRepo) {
        this.courseRepo = courseRepo;
        this.userRepo = userRepo;
        this.instructorRepo = instructorRepo;
        this.lessonRepo=lessonRepo;
        this.enrollmentRepo=enrollmentRepo;
        this.studentRepository = studentRepository;
        this.attendanceRepo=attendanceRepo;
        this.performanceRepo=performanceRepo;
    }

    public Coursedto CreateCourse(Coursedto coursedto) {
//        User user = userRepo.findById(coursedto.getUser ().getId())
//                .orElseThrow(() -> new RuntimeException("User  not found with id: " + coursedto.getUser ().getId()));

        Instructor instructor = instructorRepo.findById(coursedto.getInstructorId())
                .orElseThrow(() -> new RuntimeException("Instructor not found with id: " + coursedto.getInstructorId()));

        Course course = new Course();
        course.setTitle(coursedto.getTitle());
        course.setDescription(coursedto.getDescription());
        course.setDuration(coursedto.getDuration());
//        course.setUser (user);
        course.setInstructor(instructor);

        if (coursedto.getMediaFiles() != null) {
            for (MediaFiles mediaFile : coursedto.getMediaFiles()) {
                course.addMediaFile(mediaFile);
            }
        }

        Course savedCourse = courseRepo.save(course);
        return CourseMapper.mapToCoursedto(savedCourse);
    }

    public List<Coursedto> ViewAllCourse() {
        List<Course>courses=courseRepo.findAll();
        return courses.stream().map(course -> CourseMapper.mapToCoursedto(course)).collect(Collectors.toList());

    }

    public List<Coursedto> getCoursesByInstructor(Long instructorId) {
        List<Course> courses = courseRepo.findByInstructorId(instructorId);
        return courses.stream()
                .map(CourseMapper::mapToCoursedto)
                .collect(Collectors.toList());
    }
    public void deleteCourse(Long CourseId){

        courseRepo.deleteById(CourseId);
    }
    public Coursedto getCourseById(Long id) {
        Course course=courseRepo.findById(id).orElseThrow(() -> new RuntimeException("Course not found with id " + id));
        return CourseMapper.mapToCoursedto(course);
    }

    public Lesson addLessonToCourse(Long courseId, Lesson lesson) {
        Course course = courseRepo.findById(courseId)
                .orElseThrow(() -> new RuntimeException("Course not found with id: " + courseId));

        course.addLesson(lesson);
        return lessonRepo.save(lesson);
    }
    public void uploadMediaFiles(Long courseId, List<MultipartFile> files) {
        Course course = courseRepo.findById(courseId)
                .orElseThrow(() -> new RuntimeException("Course not found with id: " + courseId));

        for (MultipartFile file : files) {
            String uploadDir = "C:/uploads/uploads/" + courseId;
            File directory = new File(uploadDir);

            if (!directory.exists()) {
                directory.mkdirs();
            }

            try {
                String filePath = uploadDir + "/" + file.getOriginalFilename();
                file.transferTo(new File(filePath));
                MediaFiles mediaFile = new MediaFiles();
                mediaFile.setFileName(file.getOriginalFilename());
                course.addMediaFile(mediaFile);

            } catch (IOException e) {
                throw new RuntimeException("Error saving file: " + file.getOriginalFilename(), e);
            }
        }
        courseRepo.save(course);
    }
    public void enrollStudentInCourse(Long courseId, Long studentId) {
        Course course = courseRepo.findById(courseId)
                .orElseThrow(() -> new RuntimeException("Course not found with id: " + courseId));

        Student student = studentRepository.findById(studentId)
                .orElseThrow(() -> new RuntimeException("Student not found with id: " + studentId));

        Enrollment enrollment = new Enrollment();
        enrollment.setCourse(course);
        enrollment.setStudent(student);
        enrollmentRepo.save(enrollment);

        Performance performance = new Performance();
        performance.setStudent(student);
        performance.setCourse(course);
        performance.setTotalLessonsAttended(0);
        performanceRepo.save(performance);
    }

    public List<StudentDTO> getEnrolledStudents(Long courseId) {
        List<Enrollment> enrollments = enrollmentRepo.findByCourseId(courseId);
        return enrollments.stream()
                .map(enrollment -> StudentMapper.mapToStudentDTO(enrollment.getStudent()))
                .collect(Collectors.toList());
    }
    public String generateOtp(Long lessonId){
        Lesson lesson=lessonRepo.findById(lessonId).orElseThrow(()->new RuntimeException("Lesson with id not found : " + lessonId));
        String otp = String.valueOf((int)(Math.random() * 9999)+1000000);
        Attendance attendance = new Attendance();
        attendance.setLesson(lesson);
        attendance.setOtp(otp);
        attendance.setActive(true);
        attendanceRepo.save(attendance);
        return otp;

    }
    public boolean validateOtp(Long lessonId, String otp, Long studentId) {
        Attendance attendance = attendanceRepo.findByLessonIdAndOtp(lessonId, otp);
        if (attendance != null && attendance.isActive()) {
            attendance.setActive(false);
            attendance.setStudent(studentRepository.findById(studentId).orElseThrow(() -> new RuntimeException("Student not found")));
            attendanceRepo.save(attendance);
            Performance performance = performanceRepo.findByStudentIdAndCourseId(studentId, attendance.getLesson().getCourse().getId());
            if (performance != null) {
                performance.setTotalLessonsAttended(performance.getTotalLessonsAttended() + 1);
                performanceRepo.save(performance);
            }

            return true;
        }

        return false;
    }
    public int getPerformanceForStudent(Long studentId, Long courseId) {
        Performance performance = performanceRepo.findByStudentIdAndCourseId(studentId, courseId);

        if (performance == null) {
            throw new RuntimeException("Performance record not found for studentId: " + studentId + " and courseId: " + courseId);
        }

        return performance.getTotalLessonsAttended(); }
    public List<Attendancedto> getAttendanceForLesson(Long lessonId) {
        List<Attendance> attendanceList = attendanceRepo.findByLessonId(lessonId);

        return attendanceList.stream()
                .map(attendance -> {
                    Attendancedto dto = new Attendancedto();
                    dto.setStudentId(attendance.getStudent().getId());
                    dto.setLessonId(lessonId);
                    dto.setOtp(attendance.getOtp());
                    dto.setActive(attendance.isActive());
                    return dto;
                })
                .collect(Collectors.toList());
    }
    public void addQuestionsToCourse(Long courseId, List<QuestionDTO> questionDTOs) {
        Course course = courseRepo.findById(courseId)
                .orElseThrow(() -> new RuntimeException("Course not found with id: " + courseId));

        List<Question> questions = questionDTOs.stream()
                .map(questionDTO -> {
                    Question question = QuestionMapper.mapToQuestion(questionDTO, course);
                    course.addQuestion(question); // Ensure bidirectional relationship is maintained
                    return question;
                })
                .collect(Collectors.toList());

        course.getQuestionsBank().addAll(questions); // Add all questions to the course's question bank
        courseRepo.save(course);
    }

    public List<QuestionDTO> getQuestionsByCourseId(Long courseId) {
        Course course = courseRepo.findById(courseId)
                .orElseThrow(() -> new RuntimeException("Course not found with id: " + courseId));

        List<Question> questions = course.getQuestionsBank();

        return questions.stream()
                .map(QuestionMapper::mapToQuestionDTO)
                .collect(Collectors.toList());
    }

}