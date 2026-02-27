pragma circom 2.0.0;

// Vulnerable: Division without zero check
template UncheckedDivision() {
    signal input numerator;
    signal input denominator;
    signal output quotient;
    
    // Vulnerable: No check that denominator != 0
    quotient <-- numerator / denominator;
    quotient * denominator === numerator;
}

component main = UncheckedDivision();
