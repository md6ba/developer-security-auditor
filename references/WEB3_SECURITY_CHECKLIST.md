# Web3 Security Checklist

Applied when a project contains Solidity, Vyper, Move, Rust (Solana), or Rust
(ink!) sources. Static reasoning only — never sign, deploy, or transact.

## Access control and ownership

- [ ] Is there an `onlyOwner` or role-gated function that can move funds?
- [ ] Is the owner a single EOA? (Report as centralisation risk.)
- [ ] Is ownership transfer two-step (propose + accept)?
- [ ] Is there a timelock on privileged operations?
- [ ] Can ownership be renounced? What is the failure mode afterwards?
- [ ] Are role assignments emitted as events?

## Fund flows

- [ ] Is the total supply minted to a single address at deployment?
- [ ] Is there a transfer fee or tax? Is it bounded and documented?
- [ ] Can the fee recipient be changed, and by whom?
- [ ] Is there a pause mechanism? Who can pause, and can it be permanent?
- [ ] Are liquidity or approval limits enforced?

## Reentrancy and ordering

- [ ] Are state updates made before external calls (checks-effects-interactions)?
- [ ] Is a reentrancy guard present on functions that make external calls?
- [ ] Are return values of `.call`, `.send`, `.transfer` checked?
- [ ] Are `require` statements used on the result of a low-level call?

## Arithmetic

- [ ] Is SafeMath used, or is the Solidity version 0.8+?
- [ ] Are division rounding behaviours understood and documented?
- [ ] Are unbounded loops present that could exceed the block gas limit?

## External dependencies

- [ ] Is there an oracle dependency? What happens if it stalls or returns bad data?
- [ ] Are external contract addresses fixed or upgradeable?
- [ ] Are `delegatecall` or proxy patterns used? Who controls the implementation?
- [ ] Is `selfdestruct` used anywhere?

## Key and signature handling

- [ ] Are private keys or mnemonics present in source or tests?
- [ ] Is signature verification implemented correctly (EIP-712, ECDSA)?
- [ ] Is replay protection present (chain ID, nonce, domain separator)?
- [ ] Is `ecrecover` used without checking for the zero address?
- [ ] Are malleable signatures possible (missing `s` value check)?

## Randomness

- [ ] Is block.timestamp or blockhash used as a randomness source?
- [ ] Is a commit-reveal scheme used, and is it resistant to abandonment?

## Reporting rules

1. **Centralisation is not a vulnerability.** Report it as a risk with the control
   described, and let the owner decide.
2. **Never claim funds are at risk** without a concrete, demonstrable path.
3. **Never deploy, call, or sign anything.** Source-level reasoning only.
4. Distinguish a code defect from an economic design choice (fees, minting).
5. If a contract is verified on a block explorer, cite the address — but do not
   query it or interact with it.
