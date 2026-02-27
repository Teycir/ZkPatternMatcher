pragma circom 2.0.0;

// Vulnerable: Zero check without IsZero component
template MissingIsZero() {
    signal input x;
    signal output result;
    
    // Vulnerable: Using == instead of IsZero component
    if (x == 0) {
        result <== 1;
    } else {
        result <== 0;
    }
}

component main = MissingIsZero();
