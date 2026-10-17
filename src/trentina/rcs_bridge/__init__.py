"""The RCS channel bridge (#485, spec 020): one agent, one owner, one phone.

Untrusted, like the Matrix bridge: it holds the RCS provider's credentials
and nothing else. Inbound it can only hand the gateway bytes to judge;
outbound it sends only what the gateway judged.
"""
