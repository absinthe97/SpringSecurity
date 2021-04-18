package cn.lkf.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class UserController {

    @RequestMapping({"/","/index"})
    public String toIndex(){
        return "index";
    }
    @RequestMapping("adminLogin")
    public String adminLogin(){
        return "adminLogin";
    }
    @RequestMapping("userLogin")
    public String userLogin(){
        return "userLogin";
    }
}
