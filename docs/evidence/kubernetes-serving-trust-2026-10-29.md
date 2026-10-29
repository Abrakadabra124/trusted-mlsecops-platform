# Configured serving: live trust HTTP trace

Controlled synthetic component evidence. Full M11/M12 remain inconclusive; release_ready=false.

[Native run](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40811175913), job `123241583087`, source `df580e7d0b5086f67a76f9c279cd2c454586efec`.

Source fingerprint: `c0fd54822baaadd832e2e6c00f6333e2d90b3e18c1a35d1863fec1636ec665db`. Image: `sha256:ed85e290706975d1fafd60918612e33284f88abe2560c6f469e8157f57cc608e`.

Native UTC interval: `2026-10-29T03:19:03.435282+00:00` to `2026-10-29T03:22:59.861001+00:00`.

Actual candidate `4936306ee730d265554d83d059f5aee13bf81092a63b1cfbfb27eb9d57eab612` and proposal `42ac4bcabac3709ce4222fc96c834c367f662817b6686716d9ba879d40cf6522` were rejected: `release_assurance_required`, no ledger write.

Actual model `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46`; controlled fixture model `6e4e5e65497470e5fe72af895107f291245c1bfc70070378cf3cdf95d2058169`.

132 Linux test methods passed without skips. New probe/coordinator: 137/137 statements and 60/60 branches covered.

[Earlier failed run](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40809707714): initial readiness before policy-change failed. Cause remains unresolved; this successful run does not explain or prove a fix for it.

The timestamps below are seconds since the successful pre-fault HTTP request began. This is a lower bound on the last successful trust read, not its exact internal timestamp. Outage injection temporarily stops only the owned HTTP child, then continues it after the authority is stopped. Policy-change and revocation leave the child running. No clocks or production trust thresholds were changed.

| Scenario | Checks, including repeated assertions | Golden error | Elapsed seconds |
| --- | ---: | ---: | ---: |
| before_approval | 13 | None | 11.213526 |
| approved | 22 | 7.583384781240099e-08 | 15.599666 |
| after_revocation | 13 | None | 11.158621 |
| outage | 140 | 7.583384781240099e-08 | 76.183929 |
| policy-change | 32 | 7.583384781240099e-08 | 25.74627 |
| revocation | 32 | 7.583384781240099e-08 | 20.215595 |

252 checks are not 252 unique acceptance criteria. The three live traces contain 42 HTTP observations. Each fault scenario also checked 503 readiness and no automatic reactivation after recovery. Owned SQL/cluster cleanup succeeded. Raw logs and private audit data are excluded.

| Fault | Request start, s | Response complete, s | HTTP |
| --- | ---: | ---: | ---: |
| outage | 1.7601324350000027 | 1.8061008990000005 | 200 |
| outage | 3.8062212929999646 | 3.848854191999976 | 200 |
| outage | 5.848974628000008 | 5.893004997999981 | 200 |
| outage | 7.893108175999998 | 7.942300477999993 | 200 |
| outage | 9.942436041000008 | 10.004190904999973 | 200 |
| outage | 12.00429176099999 | 12.047455557999967 | 200 |
| outage | 14.047562569999968 | 14.092244662999974 | 200 |
| outage | 16.09235031099996 | 16.143501149999963 | 200 |
| outage | 18.143586836999987 | 18.192374804999986 | 200 |
| outage | 20.192494570999997 | 20.254400953000015 | 200 |
| outage | 22.25452930299997 | 22.29765366999999 | 200 |
| outage | 24.297752371 | 24.342186537999964 | 200 |
| outage | 26.34228718999998 | 26.431030201999988 | 200 |
| outage | 28.431131875999995 | 28.482525045999978 | 200 |
| outage | 30.482627013000013 | 30.539900632000013 | 200 |
| outage | 32.54000228999996 | 32.60368195000001 | 200 |
| outage | 34.603783151000016 | 34.64950990599999 | 200 |
| outage | 36.649616245999994 | 36.71690736900001 | 200 |
| outage | 38.717009292 | 38.77424887199999 | 200 |
| outage | 40.77435114899998 | 40.829706895000015 | 200 |
| outage | 42.82980537599997 | 42.881258898 | 200 |
| outage | 44.881359127999986 | 44.925658571999975 | 200 |
| outage | 46.92578209599998 | 46.99208189299998 | 200 |
| outage | 48.992180718999975 | 49.07583018999998 | 200 |
| outage | 51.07593465999997 | 51.12774909199999 | 200 |
| outage | 53.12786247599996 | 53.19823674099996 | 200 |
| outage | 55.19834200899999 | 55.240994884999964 | 200 |
| outage | 57.24109783 | 57.297574330999964 | 200 |
| outage | 59.297686946 | 59.359715505 | 200 |
| outage | 59.40980768099996 | 59.453136202999985 | 200 |
| outage | 59.503234359999965 | 59.562382550999985 | 200 |
| outage | 59.612515239000004 | 59.656029555999964 | 200 |
| outage | 59.70614856200001 | 59.74993818299998 | 200 |
| outage | 59.80003641799999 | 59.80172422300001 | 503 |
| outage | 59.85178524700001 | 59.858035762999975 | 503 |
| outage | 59.90944114499996 | 59.91083982099997 | 503 |
| outage | 59.96092783399996 | 59.96216762099999 | 503 |
| outage | 60.012257852999994 | 60.013401012999964 | 503 |
| policy-change | 5.360619708999991 | 5.383441564999998 | 503 |
| policy-change | 7.383542131000013 | 7.384885795000002 | 503 |
| revocation | 4.867073672000004 | 4.891434488000016 | 503 |
| revocation | 6.891548464000039 | 6.892898793000029 | 503 |

The outage trace has 33 successful responses within the bounded lease and 5 denials. Its first fully received 503 is at 59.80172422300001 s, and a denial is also observed after 60 s. Policy-change and revocation each produced two denials. These are component observations, not a latency SLO or acceptance of the actual candidate. Expiry, clock skew, rollback, slow trust reads, full input/privacy/retention and final same-candidate acceptance remain required.

[Implementation, failure history and runbook](../kubernetes-serving.md)
