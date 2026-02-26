pragma circom 2.0.0;

// VULNERABILITY: Underconstrained multiplication
// Source: Common pattern in zkBugs dataset
// Impact: Prover can forge arbitrary outputs
// CVE Reference: Multiple instances in zkBugs

template UnderconstrainedMultiplier() {
    signal input a;
    signal input b;
    signal output c;
    
    // BUG: Using <-- instead of <==
    // This assigns the value but doesn't create a constraint
    c <-- a * b;
    
    // MISSING: c === a * b;
    // Without this constraint, prover can set c to any value
}

component main = UnderconstrainedMultiplier();
