package com.project.app.user.entity;

public enum Role {
    ADMIN("ADMIN"),
    MANAGER("MÜDÜR"),
    PASSIVE("PASİF");


    private String value;
    public String getValue() {
        return this.value;
    }
    Role(String value) {
        this.value = value;
    }

}
