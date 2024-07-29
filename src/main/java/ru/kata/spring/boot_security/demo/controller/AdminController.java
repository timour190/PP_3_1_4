package ru.kata.spring.boot_security.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import ru.kata.spring.boot_security.demo.models.User;
import ru.kata.spring.boot_security.demo.services.RoleService;
import ru.kata.spring.boot_security.demo.services.UserService;
import ru.kata.spring.boot_security.demo.services.UserServiceImp;

import java.security.Principal;
import java.util.logging.Logger;

@Controller
@RequestMapping(value = "/admin/")
public class AdminController {

    private final UserService userService;

    private final RoleService roleService;

    private static final Logger LOGGER = Logger.getLogger(AdminController.class.getName());
    @Autowired
    public AdminController(UserService userService, RoleService roleService) {
        this.userService = userService;
        this.roleService = roleService;
    }

    @GetMapping(value = "/user")
    public String getAdmin(Model model, Principal principal) {
        LOGGER.info("Getting admin of users");
        model.addAttribute("user", userService.findUserByEmail(principal.getName()));
        return "admin/user";
    }

    @GetMapping
    public String getListUsers(Model model, Principal principal) {
        LOGGER.info("Getting list of users");
        model.addAttribute("user", userService.findUserByEmail(principal.getName()));
        model.addAttribute("users", userService.getListUsers());
        model.addAttribute("newUser", new User());
        model.addAttribute("allRoles", roleService.getListRoles());
        return "admin/list";
    }

    @GetMapping(value = "/edit")
    public String editUser(@ModelAttribute(value = "id") Long id,
                           Model model) {
        LOGGER.info("Editing user with id: " + id);
        model.addAttribute("roles", roleService.getListRoles());
        model.addAttribute("user", userService.findUser(id));
        return "admin/list";
    }

    @PatchMapping(value = "/update")
    public String updateUser(@ModelAttribute("user") User user, Long id) {
        LOGGER.info("Updating user with id: " + id);
        userService.updateUser(user, id);
        return "redirect:/admin/";
    }

    @DeleteMapping(value = "/delete")
    public String deleteUser(@ModelAttribute("id") Long id) {
        LOGGER.info("Deleting user with id: " + id);
        userService.deleteUser(id);
        return "redirect:/admin/";
    }



    @PostMapping(value = "/save")
    public String saveUser(@ModelAttribute("user") User user) {
        LOGGER.info("Saving a new user");
        String encodedPassword = new BCryptPasswordEncoder(12).encode(user.getPassword());
        user.setPassword(encodedPassword);
        userService.saveUser(user);
        return "redirect:/admin/";
    }
}


