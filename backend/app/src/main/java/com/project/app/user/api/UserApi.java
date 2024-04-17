package com.project.app.user.api;


import com.project.app.user.dto.UserDto;
import com.project.app.user.dto.UserPasswordUpdateDto;
import com.project.app.user.dto.UserSearchDto;
import com.project.app.user.repository.UserRepository;
import com.project.app.user.service.UserServiceImpl;
import com.project.app.util.ApiPathConstant;
import com.project.app.util.HeaderConstant;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping(ApiPathConstant.USER_PATH)
public class UserApi {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private UserServiceImpl userServiceImpl;

    @GetMapping("/find-by-id/{userid}")
    public ResponseEntity<UserDto> findById(
            @PathVariable long userid) throws Exception {
        return ResponseEntity.ok(userServiceImpl.findById(userid));
    }

    @PutMapping("/update-user/{userid}")
    public ResponseEntity<Boolean> updateUser(
            @PathVariable long userid,
            @Valid @RequestBody UserDto dto) throws Exception {
        return ResponseEntity.ok(userServiceImpl.update(userid, dto));
    }

    @PutMapping("/change-password/{userid}")
    public ResponseEntity<Boolean> changePassword(
            @PathVariable long userid,@Valid @RequestBody UserPasswordUpdateDto dto) throws Exception {
        return ResponseEntity.ok(userServiceImpl.changePassword(userid, dto));
    }

    @GetMapping("/search")
    public ResponseEntity<Page<UserDto>> search(
            @PageableDefault(size =25, sort = "username", direction = Sort.Direction.ASC ) Pageable page,
            @RequestHeader(HeaderConstant.AUTHORIZATION) String authHeader) throws Exception {
        Page<UserDto> list =  userServiceImpl.search(page,authHeader);
        return new ResponseEntity<Page<UserDto>>(list, new HttpHeaders(), HttpStatus.OK);
    }

    @PostMapping("/page")
    public ResponseEntity<Page<UserDto>> page(
            @PageableDefault(size =25, sort = "userId", direction = Sort.Direction.ASC ) Pageable page,
            @RequestHeader(HeaderConstant.AUTHORIZATION) String authHeader,
            @RequestBody UserSearchDto dto) throws Exception {
        return ResponseEntity.ok(userServiceImpl.page(page,authHeader, dto));

    }

    @GetMapping
    public ResponseEntity<UserDto> getYourSelf(
            @RequestHeader(HeaderConstant.AUTHORIZATION) String authHeader) throws Exception {
        return ResponseEntity.ok(userServiceImpl.getYourSelf(authHeader));
    }

    @PostMapping("/update-my-password")
    public ResponseEntity<?> updateMyPassword(
            @RequestHeader(HeaderConstant.AUTHORIZATION) String authHeader,
            @RequestBody UserPasswordUpdateDto dto) throws Exception {
        return ResponseEntity.ok(userServiceImpl.updateMyPassword(authHeader,dto));
    }

    @PutMapping("update/{username}")
    public ResponseEntity<Boolean> updateYourSelf(
            @RequestHeader(HeaderConstant.AUTHORIZATION) String authHeader,
            @Valid @RequestBody UserDto userDto) throws Exception {
        return ResponseEntity.ok(userServiceImpl.updateYourSelf(authHeader, userDto));
    }
}
