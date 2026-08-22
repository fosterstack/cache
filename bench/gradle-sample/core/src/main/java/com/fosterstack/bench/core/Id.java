package com.fosterstack.bench.core;

import java.util.UUID;

public record Id(UUID value) {
    public static Id random() {
        return new Id(UUID.randomUUID());
    }

    public static Id of(String s) {
        return new Id(UUID.fromString(s));
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
