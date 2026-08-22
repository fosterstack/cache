package com.fosterstack.bench.c;

import com.fosterstack.bench.a.Order;
import com.fosterstack.bench.b.Ledger;
import com.fosterstack.bench.core.Money;

public final class Checkout {
    private final Ledger ledger;

    public Checkout(Ledger ledger) {
        this.ledger = ledger;
    }

    public Money settle(Order order, String currency) {
        Money total = order.total(currency);
        ledger.credit(order.id(), total);
        return total;
    }
}
