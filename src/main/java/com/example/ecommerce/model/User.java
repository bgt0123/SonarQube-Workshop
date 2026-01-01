package com.example.ecommerce.model;

import java.util.Date;

/**
 * User entity
 */
public class User {

    // Public fields - Encapsulation Problem
    public int id;
    public String email;

    private String password; // Sollte gehashed sein
    private String firstName;
    private String lastName;
    private int age;
    private String country;
    private String cantonCode;
    private int totalOrders;
    private double totalSpent;
    private boolean premium;
    private String[] orderHistory;
    private Date createdAt;

    // Kein Constructor

    // Getters und Setters ohne Validierung
    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email; // Keine Email-Validierung
    }

    public String getPassword() {
        return password; // Password sollte nie zurückgegeben werden
    }

    public void setPassword(String password) {
        this.password = password; // Sollte gehashed werden
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age; // Keine Validierung (negative Zahlen möglich)
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public String getCantonCode() {
        return cantonCode;
    }

    public void setCantonCode(String cantonCode) {
        this.cantonCode = cantonCode;
    }

    public int getTotalOrders() {
        return totalOrders;
    }

    public void setTotalOrders(int totalOrders) {
        this.totalOrders = totalOrders;
    }

    public double getTotalSpent() {
        return totalSpent;
    }

    public void setTotalSpent(double totalSpent) {
        this.totalSpent = totalSpent;
    }

    public boolean isPremium() {
        return premium;
    }

    public void setPremium(boolean premium) {
        this.premium = premium;
    }

    public String[] getOrderHistory() {
        return orderHistory; // Array wird direkt zurückgegeben - mutable
    }

    public void setOrderHistory(String[] orderHistory) {
        this.orderHistory = orderHistory; // Direkte Zuweisung ohne Kopie
    }

    public Date getCreatedAt() {
        return createdAt; // Mutable Date wird zurückgegeben
    }

    public void setCreatedAt(Date createdAt) {
        this.createdAt = createdAt;
    }

    // equals() fehlt (sollte implementiert sein für Entity)
    // hashCode() fehlt
    // toString() fehlt
}
