package com.example.ecommerce;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import com.example.ecommerce.model.User;
import com.example.ecommerce.model.Order;
import com.example.ecommerce.model.OrderStatus;
import com.example.ecommerce.repository.UserRepository;
import com.example.ecommerce.repository.OrderRepository;

@SpringBootApplication
public class ECommerceShop {

    public static void main(String[] args) {
        SpringApplication.run(ECommerceShop.class, args);
    }
}
