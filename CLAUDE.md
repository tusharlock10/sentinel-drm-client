# Sentinel DRM Backend — Claude Context

Sentinel DRM is QNu Lab's multi-tenant Digital Rights Management platform for license issuance, software distribution, and runtime license enforcement for enterprise clients. 
This is the Sentinel client which enforces licensing on the customer machine and protects QNu's software from illegitimate use.

## Golang version and libraries 
1. go 1.26+
2. cobra - cli library
3. memguard - memory security
4. garble - binary obfuscation

### Coding Preferences
1. The claude agent should ask any clarification questions in the planning phase before starting implementation.
2. If certain points of the task are ambiguous then ask the user for clarification and doubts rather than assuming.
3. Validate first, fail fast and loud rather than trying to circumvent improper user inputs and niche or undefined behaviors.  
4. Do not add unnecessary fallbacks or defaults, until and unless it is crucial or very logical to add a default or fallback for some piece of code. Unnecessary fallbacks create bloat and introduce silent bugs in the software and should be avoided.
5. Keep code lean and clean, add documentation where necessary and required, do not add unnecessary comments.
6. Prefer stdlib, introduce deps only with clear payoff.
7. Do not run commands that modify the project or add packages on your own. Ask the user to run them instead giving a proper reason why is it required.
8. Do not perform premature optimization, first create the functionality in simple and robust way, then ask the user if further optimization is required.