package com.fosterstack.bench.b;

import com.fosterstack.bench.core.Id;
import com.fosterstack.bench.core.Money;

import java.util.LinkedHashMap;
import java.util.Map;

public final class Ledger {
    private final Map<Id, Money> balances = new LinkedHashMap<>();

    public void credit(Id account, Money amount) {
        balances.merge(account, amount, Money::add);
    }

    public Money balanceOf(Id account, String currency) {
        return balances.getOrDefault(account, new Money(0, currency));
    }

    public int accountCount() {
        return balances.size();
    }
}
