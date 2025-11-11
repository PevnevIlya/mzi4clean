package com.example.AuthenticationService.entity;

public class DecryptResponse {
    private String text;

    public DecryptResponse(String text) { this.text = text; }
    public String getText() { return text; }
    public void setText(String text) { this.text = text; }
}
