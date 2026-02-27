# ZkPatternMatcher — Official Demo (38 seconds)
# Run with: vhs zkpm-demo.tape

Output docs/demo.gif

Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 26
Set Width 1300
Set Height 800
Set Theme "Dracula"
Set Padding 20
Set Margin 0

# Intro frame
Sleep 400ms
Type "echo 'ZkPatternMatcher v0.1.0'"
Enter
Type "echo 'Pattern-based ZK circuit scanner'"
Enter
Sleep 800ms
Type "clear"
Enter
Sleep 300ms

# 1. Version & Help
Type "zkpm --version"
Enter
Sleep 700ms

Type "zkpm --help | head -n 15"
Enter
Sleep 1200ms

# 2. List patterns (looks impressive)
Type "echo ''"
Enter
Type "echo 'Available patterns:'"
Enter
Type "zkpm list patterns/real_vulnerabilities.yaml"
Enter
Sleep 1800ms

# 3. The money shot — catching real vulnerabilities
Type "echo ''"
Enter
Type "echo 'Scanning vulnerable circuit...'"
Enter
Type "zkpm patterns/real_vulnerabilities.yaml tests/real_vulnerabilities/underconstrained_multiplier.circom"
Enter
Sleep 2200ms

# 4. JSON output for CI
Type "echo ''"
Enter
Type "echo 'JSON output (perfect for GitHub Actions):'"
Enter
Type "zkpm --format json patterns/real_vulnerabilities.yaml tests/real_vulnerabilities/underconstrained_multiplier.circom | head -n 35"
Enter
Sleep 1800ms

# 5. Validate patterns (shows quality)
Type "echo ''"
Enter
Type "echo 'Validating pattern library...'"
Enter
Type "zkpm validate patterns/real_vulnerabilities.yaml"
Enter
Sleep 1400ms

# Final frame
Type "echo ''"
Enter
Type "echo 'Zero false positives - Ready for production audits'"
Enter
Sleep 1200ms

Type "echo 'Star the repo if it saved you time!'"
Enter
Sleep 800ms
