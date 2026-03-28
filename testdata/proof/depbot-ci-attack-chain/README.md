# Depbot CI Attack Chain
Demonstrates COR-006 correlation: Renovate config without minimumReleaseAge combined with package.json install hooks. A compromised upstream package triggers a Renovate PR — CI runs npm install on the PR branch, executing the malicious install hook on the runner before any human review.
