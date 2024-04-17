package com.project.app.user.service;

import com.project.app.user.dto.UserDto;
import com.project.app.user.dto.UserPasswordUpdateDto;
import com.project.app.user.dto.UserSaveDto;
import com.project.app.user.dto.UserSearchDto;
import com.project.app.user.entity.Role;
import com.project.app.user.entity.User;
import com.project.app.user.repository.UserRepository;
import jakarta.persistence.EntityManager;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Slf4j
@Service
@Transactional
public class UserServiceImpl {


    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ModelMapper mapper;
    @Autowired
    private ControlService controlService;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private EntityManager entityManager;

    public Boolean save(UserSaveDto dto) {
        try {
            User user = mapper.map(dto, User.class);
            user.setUsername(user.getUsername().trim());
            user.setPassword(user.getPassword().trim());
            user.setStatus(1);
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            user = userRepository.save(user);
            return true;
        } catch (Exception e) {
            throw e;
        }
    }

    public User findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElse(null);
    }

    public UserDto getYourSelf(String authHeader) throws Exception {
        User user = controlService.getUserFromToken(authHeader);
        UserDto dto = mapper.map(user, UserDto.class);
        return dto;
    }

    public Boolean update(long userid, UserDto dto) throws Exception {
        Optional<User> opt = userRepository.findById(userid);
        if (!opt.isPresent()) {
            log.error("Böyle bir kullanıcı yoktur.");
            throw new Exception("Böyle bir kullanıcı yoktur.");
        }
        User user = opt.get();
        user.setName(dto.getName());
        user.setSurname(dto.getSurname());
        user.setUsername(dto.getUsername());
        user.setRole(dto.getRole());
        user = userRepository.save(user);
        return true;
    }

    public Boolean updateYourSelf(String authHeader, UserDto userDto) throws Exception {
        User user = controlService.getUserFromToken(authHeader);
        user.setUsername(userDto.getUsername().trim());
        user.setName(userDto.getName().trim());
        user.setSurname(userDto.getSurname().trim());
        user = userRepository.save(user);
        return true;
    }

    public UserDto findById(long userid) throws Exception {
        Optional<User> opt = userRepository.findById(userid);
        if (!opt.isPresent()) {
            log.error("Böyle bir kullanıcı yoktur.");
            throw new Exception("Böyle bir kullanıcı yoktur.");
        }
        log.info("Kullanıcı Bulundu.");
        User user = opt.get();
        UserDto dto = mapper.map(user, UserDto.class);
        return dto;
    }

    public ResponseEntity<?> updateMyPassword(String authHeader, UserPasswordUpdateDto dto) throws Exception {
        User user = controlService.getUserFromToken(authHeader);
        boolean result = false;
        if (dto.getNewPassword().equals(dto.getRepeatNewPassword())) {
            if (passwordEncoder.matches(dto.getOldPassword(), user.getPassword())) {
                user.setPassword(passwordEncoder.encode(dto.getNewPassword()));
                userRepository.save(user);
                result = true;
            }
        }else{
            throw new IllegalArgumentException("Şifreler uyuşmuyor.");
        }
        return ResponseEntity.ok(result);
    }

    public Boolean changePassword(long userid, UserPasswordUpdateDto dto) throws Exception {
        Optional<User> opt = userRepository.findById(userid);
        if (!opt.isPresent()) {
            log.error("Böyle bir kullanıcı yoktur.");
            throw new Exception("Böyle bir kullanıcı yoktur.");
        }
        boolean result = false;
        User user = opt.get();
        if (dto.getNewPassword().equals(dto.getRepeatNewPassword())) {
            user.setPassword(passwordEncoder.encode(dto.getNewPassword()));
            user = userRepository.save(user);
            result = true;
        } else {
            throw new Exception("Girdiğiniz Şifreler uyuşmamaktadır.");
        }
        return result;
    }

    public Page<UserDto> search(Pageable page, String authHeader) throws Exception {

        User user = controlService.getUserFromToken(authHeader);
        Page<User> list = userRepository.findByUsernameNot(user.getUsername(), page);
        Page<UserDto> pageList = list.map(UserDto::new);
        return pageList;
    }

    public Page<UserDto> page(Pageable page, String authHeader, UserSearchDto dto) throws Exception {

        try {
            StringBuilder createSqlQuery = new StringBuilder("select * from users u where 1=1 ");

            if (dto.getName() != null){
                createSqlQuery.append(" and u.name ILIKE '%" + dto.getName() + "%'");
            }
            if (dto.getSurname() != null){
                createSqlQuery.append(" and u.surname ILIKE '%" + dto.getSurname() + "%'");
            }
            if (dto.getUsername() != null){
                createSqlQuery.append(" and u.username ILIKE '%" + dto.getUsername() + "%'");
            }
            if (dto.getRole() != null){
                createSqlQuery.append(" and u.role ILIKE '%" + dto.getRole().toString() + "%'");
            }
            createSqlQuery.append(" order by u.username");

            List<Object> list = entityManager.createNativeQuery(createSqlQuery.toString(), User.class).getResultList();

            UserDto[] dtos = mapper.map(list, UserDto[].class);
            List<UserDto> dtosList = Arrays.asList(dtos);

            int start = Math.min((int) page.getOffset(), dtosList.size());
            int end = Math.min((start + page.getPageSize()), dtosList.size());

            Page<UserDto> pageList = new PageImpl<>(dtosList.subList(start, end), page, dtosList.size());
            return pageList;
        } catch (Exception e) {
            throw e;
        }
    }
}
