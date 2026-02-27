pragma circom 2.0.0;

// Vulnerable: Using == instead of ===
template EqualityNoConstraint() {
    signal input a;
    signal input b;
    signal output equal;
    
    // Vulnerable: == doesn't create constraint, === does
    if (a == b) {
        equal <== 1;
    } else {
        equal <== 0;
    }
}

component main = EqualityNoConstraint();
