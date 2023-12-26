package com.mudra.bootsecurity;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.view.RedirectView;

@Controller
public class CarsOnlineController {

    @GetMapping("/")
    public RedirectView redirectToCars() {
        return new RedirectView("/carsonline");
    }

    @GetMapping("/carsonline")
    public String carsOnline() {
        return "carsonline";
    }

    @GetMapping("/buyCar")
    public String buyCar() {
        return "buycar";
    }

    @GetMapping("/editCar")
    public String editCar() {
        return "editCars";
    }
}
