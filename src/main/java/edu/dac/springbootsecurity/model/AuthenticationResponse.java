package edu.dac.springbootsecurity.model;

public class AuthenticationResponse {
  private String token;

  public AuthenticationResponse(String token) {
    this.token = token;
  }

  public AuthenticationResponse() {
  }

  public String getToken() {
    return token;
  }

  public void setToken(String token) {
    this.token = token;
  }
}
