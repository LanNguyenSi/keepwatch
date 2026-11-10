package probes

// AptPolicyShape is the shape classifyAptPolicyLine gives a line of
// "apt-cache policy" output, "" for a line it does not know.
func AptPolicyShape(line string) string { return classifyAptPolicyLine(line).shape }
