pragma circom 2.0.0;

// Safe circuit: Properly constrained multiplier
template SafeMultiplier() {
    signal input a;
    signal input b;
    signal output c;

    // Properly constrained with constraint operator
    c <== a * b;
}

component main = SafeMultiplier();
