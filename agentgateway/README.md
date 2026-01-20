Running notes about where Agentgateway can fit into this picture:

* the biggest way is in implementing the RFC 9421 / signature-key spec: https://github.com/dickhardt/signature-key/tree/main
* from here we can require things like psudonymous or identified traffic, ie, we can require minimum and implement things like 401 for specific agents/mcp tools and require upgrade. 
* can implement rate limit and offer different RL policies based on anonymous/psuedonomous/identified traffic including step-up after certain classes of Rate limit
* can implement identity based usage policies here; ie, after message signature, if jwks is used, use the agent identity (https://foo.agent) for specific policies that are based on identity
* can call out to OPA/OpenFGA,etc
* can require authz token for certain routes: if agent as resource scenario, can help facilitate tokens? need to investigate this; can we respond with resource tokens? prob not... but should investigate