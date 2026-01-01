package com.example.ecommerce.repository;

import com.example.ecommerce.service.UserService;
import com.example.ecommerce.model.Order;
import com.example.ecommerce.model.User;
import java.util.*;

/**
 * Order Repository
 */
public class OrderRepository {

    private UserService userService; // Circular Dependency!
    private Map<Integer, Order> orderCache = new HashMap<>();

    // Setter wird von UserService aufgerufen - erstellt Zyklus
    public void setUserService(UserService userService) {
        this.userService = userService;
    }

    // Diese Methode benötigt UserService, UserService benötigt OrderRepository
    public List<Order> getOrdersForUser(String email) {
        try {
            User user = userService.getUserByEmail(email);
            if (user == null) {
                return Collections.emptyList();
            }
            return getOrdersByUserId(user.getId());
        } catch (Exception e) {
            e.printStackTrace(); // Logging über printStackTrace
            return null; // Returning null from Collection-Method
        }
    }

    private List<Order> getOrdersByUserId(int userId) {
        List<Order> orders = new ArrayList<>();
        for (Order order : orderCache.values()) {
            if (order.getUserId() == userId) {
                orders.add(order);
            }
        }
        return orders;
    }

    // Thread-Safety Problem - nicht synchronisierter Zugriff auf shared mutable state
    public void addOrder(Order order) {
        orderCache.put(order.getId(), order);
    }

    public Order getOrder(int id) {
        return orderCache.get(id);
    }
}