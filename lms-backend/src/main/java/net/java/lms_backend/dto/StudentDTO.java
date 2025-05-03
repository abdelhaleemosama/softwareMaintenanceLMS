package net.java.lms_backend.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter

public class StudentDTO {
    private Long id;
    private String username;
    private String email;
    public StudentDTO(Long id, String username,String email){
        this.id=id;
        this.email=email;
        this.username=username;
    }
    public  StudentDTO(){
    }

    public Long getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public String getUsername() {
        return username;
    }
}
