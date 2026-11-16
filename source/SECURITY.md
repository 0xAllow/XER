# Security policy

XER v0.0 is an experimental, unaudited preview. Do not expose the receiver directly to untrusted networks or depend on it for irreplaceable data.

Report suspected vulnerabilities privately to the repository maintainer through GitHub private vulnerability reporting, if enabled. Do not post exploitable details in public issues.

The HTTPS first-use pairing code MUST be compared on both devices over a trusted channel. Do not approve unexpected pairing prompts. SSH/SFTP requires an independently verified host key; XER does not replace OpenSSH server setup.

Never commit a real `config.toml`, device state, logs containing sensitive paths, keys, generated credentials, or private signing material.

No independent security audit has been performed. Version 0.0 carries no stable security support promise.
