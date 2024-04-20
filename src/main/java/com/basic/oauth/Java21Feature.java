package com.basic.oauth;

public class Java21Feature {
    public static void main(String[] args) {
        System.out.println(message(new SecuredLoan(20.0f)));
        System.out.println(message(new UnSecuredLoan(22.0f)));
    }

    private static String message(Loan loan) {
        return switch (loan) {
            case SecuredLoan(var interest) -> "secured loan " + interest;
            case UnSecuredLoan usl -> "unsecured loan " + usl.interest();
        };
    }
}

sealed interface Loan permits SecuredLoan, UnSecuredLoan {
}

record SecuredLoan(float interest) implements Loan {
}

record UnSecuredLoan(float interest) implements Loan {
}

