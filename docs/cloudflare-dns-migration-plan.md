# Historical: apt.to Cloudflare DNS migration plan

> Superseded by the `getpatched.dev` domain choice. The observations below document the former `apt.to` setup only; do not use this plan to modify DNS or Cloudflare resources for the current project.

Prepared 26 October 2026 from Cloudflare API, public DNS, and RDAP checks. This is a proposed change plan; no nameserver, DNS-record, or Worker mutation has been made. The dedicated private R2 bucket `getpatched-release-staging` has been created; no AptTo objects have been uploaded.

## Verified current state

- The Cloudflare API token used for read-only checks sees the `Diderichsen` account. Its `apt.to` full zone is `pending`, has zero DNS records, and is assigned `kia.ns.cloudflare.com` and `terin.ns.cloudflare.com`.
- Account inventory is 12 Workers, five R2 buckets, and 10 Pages projects. The `getpatched-release-staging` bucket is the only AptTo-named resource and is private; no AptTo Worker exists. The four pre-existing R2 buckets and all existing Workers and Pages projects were left unchanged.
- Public DNS delegates `apt.to` to `ns1.afternic.com` and `ns2.afternic.com`. The registrar identified in public RDAP is Tonic. Confirm the actual registrar account and any forwarding or domain-level services in Tonic before changing delegation; public RDAP does not prove account access or expose all registrar settings.
- Current public answers for `apt.to`, `www.apt.to`, `repo.apt.to`, and `early.apt.to` are the Afternic parking A records `13.248.169.48` and `76.223.54.146`, TTL 3600 seconds. The root has Null MX (`0 .`) and TXT `v=spf1 -all`; no AAAA or CAA answer for the apex was returned. A query to the public resolver returned no DS answer, but verify DNSSEC/DS in Tonic immediately before cutover.
- The Worker config declares custom domains for `apt.to`, `repo.apt.to`, and `early.apt.to`. Cloudflare requires an active zone for Worker custom domains and creates their DNS records and certificates. `www.apt.to` is not a configured Worker hostname and should remain parked unless a separate redirect is designed and approved.

## Proposed staged change

1. Before any write, obtain a dedicated Cloudflare API token with only the required DNS write/read scope for the `apt.to` zone. Do not use or copy the existing account credential into GitHub. Confirm a least-privilege Worker deployment token, private R2 access, GitHub environment protection, signing custody, and runtime secrets separately; these remain launch gates.
2. With approval, prepopulate the pending Cloudflare zone to preserve current DNS answers during delegation: two parking A records each for the apex, `www`, `repo`, and `early`; the root Null MX; and the existing SPF TXT. Keep the records DNS-only until the relevant Worker custom domains are deliberately created. Verify every record by readback before changing registrar delegation.
3. With explicit domain-owner approval, change the nameservers in the Tonic registrar account to exactly `kia.ns.cloudflare.com` and `terin.ns.cloudflare.com`, removing the old Afternic nameservers. This replaces Afternic as authoritative DNS and ends its parking service once caches expire. Keep the Afternic configuration intact for rollback.
4. Verify the parent delegation with `dig +trace NS apt.to`, check DS/DNSSEC and Cloudflare zone activation, and query each preserved record through multiple public resolvers. Stop if the zone is not active, the answers differ from the verified inventory, DNSSEC fails, or an unrecorded service is discovered.
5. Only after the zone is active and deployment prerequisites pass, manually deploy the reviewed Worker using the protected deployment workflow. Cloudflare should create the three configured custom-domain records and TLS certificates. Preserve `www` parking; do not create a redirect or delete unrelated records in this change. Verify `apt.to`, `repo.apt.to`, and `early.apt.to` over HTTPS, signed public/early metadata, auth isolation, and APT client flows before treating the service as live.
6. Roll back by restoring the exact previous Afternic nameservers at Tonic if Cloudflare activation or the approved deployment fails. DNS caches can delay rollback; retain the current parking answers and all existing account resources throughout. Do not delete the Cloudflare zone or other resources as part of rollback.

The zone is not ready for steps 2–5 today: the dedicated least-privilege write/deploy credential path, independent GitHub environment reviewer, signing configuration, runtime secrets, and user approval of the Afternic parking replacement are not established. No service outage is authorized by this plan.

## References

- [Cloudflare zone status and Pending state](https://developers.cloudflare.com/dns/zone-setups/reference/domain-status/)
- [Cloudflare pending nameserver troubleshooting](https://developers.cloudflare.com/dns/zone-setups/troubleshooting/pending-nameservers/)
- [Cloudflare full DNS setup](https://developers.cloudflare.com/dns/zone-setups/full-setup/setup/)
- [Cloudflare Worker Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/)
