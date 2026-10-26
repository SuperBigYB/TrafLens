# TrafLens

TrafLens is a distribution and continued development of the DeepFlow open-source
observability core, starting from upstream commit
`8741e924ff0ae3964a135985c51e5a6ce6bde397`. The original upstream README, licenses,
copyright notices, history, module names and protocol definitions are preserved.

Development checkout: `dev-79:/root/yb/git/TrafLens`. The test peer is `dev-240`.
Both machines provide two directly connected 10 GbE ports. The target is to
validate and extend functionality and performance against explicit DeepFlow
edition/version baselines. Source import alone does not establish parity.

See [distribution workflow](traflens/README.md),
[source provenance](traflens/upstream.json), and
[development state](traflens/STATE.md) for current evidence and next steps.

The upstream community core uses Apache-2.0. Separate upstream GUI/application
projects use other licenses and must be reviewed when incorporated. DeepFlow is
the upstream product name; TrafLens does not assert upstream endorsement.
