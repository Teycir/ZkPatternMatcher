pragma circom 2.0.0;

// Vulnerable: Loop with unbounded variable
template UnboundedLoop() {
    signal input n;
    signal output result;
    
    var sum = 0;
    // Vulnerable: Loop bound depends on input variable
    for (var i = 0; i < n; i++) {
        sum += i;
    }
    
    result <== sum;
}

component main = UnboundedLoop();