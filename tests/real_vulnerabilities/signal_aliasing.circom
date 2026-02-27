pragma circom 2.0.0;

// Vulnerable: Signal aliasing through array indexing
template SignalAliasing() {
    signal input a;
    signal input b;
    signal output c;
    
    signal intermediate[2];
    
    // Vulnerable: Both array elements could alias the same constraint
    intermediate[0] <-- a;
    intermediate[1] <-- b;
    
    // Missing constraint: intermediate values not constrained
    c <== intermediate[0] + intermediate[1];
}

component main = SignalAliasing();
