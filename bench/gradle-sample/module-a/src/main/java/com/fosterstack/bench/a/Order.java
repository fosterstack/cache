package com.fosterstack.bench.a;

import com.fosterstack.bench.core.Id;
import com.fosterstack.bench.core.Money;

import java.util.ArrayList;
import java.util.List;

public final class Order {
    private final Id id = Id.random();
    private final List<Money> lineItems = new ArrayList<>();

    public Order addLineItem(Money amount) {
        lineItems.add(amount);
        return this;
    }

    public Money total(String currency) {
        Money total = new Money(0, currency);
        for (Money item : lineItems) {
            total = total.add(item);
        }
        return total;
    }

    public Id id() {
        return id;
    }
}
