package com.example.AuthenticationService.controller;

import com.example.AuthenticationService.dto.StatsDto;
import com.example.AuthenticationService.service.StatsService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class StatsController {
    private final StatsService statsService;

    public StatsController(StatsService statsService) {
        this.statsService = statsService;
    }

    @GetMapping("/stats")
    public ResponseEntity<StatsDto> stats(@RequestHeader(value = "Authorization", required = false) String auth) {
        StatsDto dto = new StatsDto(statsService.getEncryptBytes(), statsService.getDecryptBytes());
        return ResponseEntity.ok(dto);
    }
}
