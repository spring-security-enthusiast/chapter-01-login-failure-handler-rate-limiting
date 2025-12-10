# Chapter 01 – Login Basics

This chapter introduces the foundations of Spring Security’s form login using real, working code.

Spring Security can feel overwhelming at first because many things happen “behind the scenes”.
In this chapter, we slow everything down and focus on how login actually works, step by step.

This project is intentionally kept simple and focused — no databases, no JWT, no OAuth, no microservices.

# 🎯What You Will Learn
By the end of this chapter, you will understand:
* How Spring Security enables form-based login
* Where the login page comes from
* What happens when login succeeds or fails
* How Spring Security decides who can access which URL

# 🧱 What This Chapter Covers✅ 

Included in this project:
* Custom login page (Thymeleaf)
* Default Spring Security filter chain
* Username + password authentication
* Redirect behavior after login
* Basic protected and public endpoints

# 🚫 Not covered yet (intentionally):
* Logout
* Remember-me
* CSRF deep dive
* OAuth2 / JWT / Keycloak
* Database-backed users

Each concept above will be introduced gradually in later chapters.


# 🚀 How to Run the Project
Prerequisites
* Java 17+
* Maven
* (Optional) IntelliJ IDEA

## Start the application
```java
./mvnw spring-boot:run
```
or from IDE:
```aiignore
Run DemoApplication.java
```

## Open in browser
* Login page:
  * 👉 http://localhost:8080/login
* Protected page (requires login):
  * 👉 http://localhost:8080/home 


## Default User
This demo uses an in-memory user:
* Username: admin
* Password: password