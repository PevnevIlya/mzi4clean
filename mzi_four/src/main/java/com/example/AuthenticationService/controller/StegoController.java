package com.example.AuthenticationService.controller;

import com.example.AuthenticationService.service.StegoService;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/stego")
@CrossOrigin
public class StegoController {

    private final StegoService stegoService;

    public StegoController(StegoService stegoService) {
        this.stegoService = stegoService;
    }

    @PostMapping(value = "/hide", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<byte[]> hide(
            @RequestParam("image") MultipartFile image,
            @RequestParam("message") String message) throws Exception {

        byte[] result = stegoService.hideMessage(image, message);
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.IMAGE_JPEG);
        h.setContentDisposition(ContentDisposition.attachment().filename("stego.jpg").build());
        return new ResponseEntity<>(result, h, HttpStatus.OK);
    }

    @PostMapping(value = "/extract", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> extract(@RequestParam("image") MultipartFile image) throws Exception {
        String text = stegoService.extractMessage(image);
        return ResponseEntity.ok(text.isEmpty() ? "No hidden message" : text);
    }
}