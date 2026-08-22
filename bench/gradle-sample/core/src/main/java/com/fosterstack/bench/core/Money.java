package com.fosterstack.bench.core;

import java.util.Objects;

public final class Money {
    private final long cents;
    private final String currency;

    public Money(long cents, String currency) {
        this.cents = cents;
        this.currency = Objects.requireNonNull(currency);
    }

    public long cents() {
        return cents;
    }

    public String currency() {
        return currency;
    }

    public Money add(Money other) {
        if (!currency.equals(other.currency)) {
            throw new IllegalArgumentException("currency mismatch: " + currency + " vs " + other.currency);
        }
        return new Money(cents + other.cents, currency);
    }

    @Override
    public String toString() {
        return String.format("%d.%02d %s", cents / 100, Math.abs(cents % 100), currency);
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Money m)) return false;
        return cents == m.cents && currency.equals(m.currency);
    }

    @Override
    public int hashCode() {
        return Objects.hash(cents, currency);
    }
}
