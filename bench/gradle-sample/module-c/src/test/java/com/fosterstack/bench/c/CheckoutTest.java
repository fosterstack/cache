package com.fosterstack.bench.c;

import com.fosterstack.bench.a.Order;
import com.fosterstack.bench.b.Ledger;
import com.fosterstack.bench.core.Id;
import com.fosterstack.bench.core.Money;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CheckoutTest {
    @Test
    void settleCreditsTheLedgerForTheOrderTotal() {
        Ledger ledger = new Ledger();
        Checkout checkout = new Checkout(ledger);
        Order order = new Order()
                .addLineItem(new Money(500, "USD"))
                .addLineItem(new Money(250, "USD"));

        Money settled = checkout.settle(order, "USD");

        assertEquals(new Money(750, "USD"), settled);
        assertEquals(new Money(750, "USD"), ledger.balanceOf(order.id(), "USD"));
    }

    @Test
    void unknownAccountHasZeroBalance() {
        Ledger ledger = new Ledger();
        assertEquals(new Money(0, "USD"), ledger.balanceOf(Id.random(), "USD"));
    }
}
