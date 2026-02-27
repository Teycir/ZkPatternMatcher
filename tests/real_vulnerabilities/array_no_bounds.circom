pragma circom 2.0.0;

// Vulnerable: Array access without bounds check
template ArrayNoBounds() {
    signal input index;
    signal input values[10];
    signal output result;
    
    // Vulnerable: No check that index < 10
    result <== values[index];
}

component main = ArrayNoBounds();
