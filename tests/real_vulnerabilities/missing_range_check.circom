pragma circom 2.0.0;

// VULNERABILITY: Missing range constraint
// Source: zkBugs - Multiple projects
// Impact: Values can overflow field boundaries
// Pattern: Signal without proper bounds checking

template MissingRangeCheck() {
    signal input value;
    signal output isValid;
    
    // BUG: No constraint that value is in valid range [0, 2^32)
    // Attacker can use values >= 2^32 that wrap around
    
    // This just copies the input without validation
    isValid <== value;
    
    // MISSING: Range check constraint
    // Should use Num2Bits or explicit range proof
}

component main = MissingRangeCheck();
