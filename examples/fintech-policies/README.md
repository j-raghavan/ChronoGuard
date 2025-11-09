# Financial Services Policy Examples

OPA policies tailored for financial services compliance (SOX, FINRA, SEC).

## Policies

### trading-hours.rego
- NYSE/NASDAQ trading hours enforcement
- Market holiday calendar
- Extended hours trading controls
- **Compliance**: Prevents unauthorized after-hours access

### compliance-domains.rego
- Approved market data provider allowlist
- Production trading system access controls
- Social media blocking (prevent insider trading signals)
- **Compliance**: SOX segregation of duties, FINRA supervision

### risk-management.rego
- Risk-based access control by agent type
- Trading velocity limits
- Market circuit breaker integration
- **Compliance**: Risk management frameworks, position limits

## Usage

Deploy all three for comprehensive fintech compliance:

```bash
cp *.rego /path/to/chronoguard/configs/opa/policies/fintech/
docker compose restart chronoguard-policy-engine
```

**Note**: These policies demonstrate compliance patterns but should be customized for your specific regulatory requirements.
