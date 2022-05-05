package be.vdab.beveiligd.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("offertes")
class OfferteController {
    @GetMapping
    public String offertes() {
        return "offertes";
    }
}
