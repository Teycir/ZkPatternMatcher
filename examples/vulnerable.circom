pragma circom 2.0.0;

template VulnerableCircuit() {
    signal input a;
    signal input b;
    signal output c;
    
    // VULNERABILITY: Unconstrained assignment
    c <-- a * b;
    
    // Missing constraint: c === a * b
}

component main = VulnerableCircuit();
