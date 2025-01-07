
namespace: secops, deployment: juice-shop
=========================================
Total: 25 (UNKNOWN: 1, LOW: 14, MEDIUM: 10, HIGH: 0, CRITICAL: 0)

┌────────────┬──────────────────┬──────────┬──────────────┬───────────────────┬──────────────────┬─────────────────────────────────────────────────────────────┐
│  Library   │  Vulnerability   │ Severity │    Status    │ Installed Version │  Fixed Version   │                            Title                            │
├────────────┼──────────────────┼──────────┼──────────────┼───────────────────┼──────────────────┼─────────────────────────────────────────────────────────────┤
│ libc6      │ CVE-2023-4806    │ MEDIUM   │ will_not_fix │ 2.31-13+deb11u10  │                  │ glibc: potential use-after-free in getaddrinfo()            │
│            │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-4806                   │
│            ├──────────────────┤          ├──────────────┤                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│            │ CVE-2023-4813    │          │ affected     │                   │                  │ glibc: potential use-after-free in gaih_inet()              │
│            │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-4813                   │
│            ├──────────────────┼──────────┤              │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│            │ CVE-2010-4756    │ LOW      │              │                   │                  │ glibc: glob implementation can cause excessive CPU and      │
│            │                  │          │              │                   │                  │ memory consumption due to...                                │
│            │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2010-4756                   │
│            ├──────────────────┤          │              │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│            │ CVE-2018-20796   │          │              │                   │                  │ glibc: uncontrolled recursion in function                   │
│            │                  │          │              │                   │                  │ check_dst_limits_calc_pos_1 in posix/regexec.c              │
│            │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2018-20796                  │
│            ├──────────────────┤          │              │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│            │ CVE-2019-1010022 │          │              │                   │                  │ glibc: stack guard protection bypass                        │
│            │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2019-1010022                │
│            ├──────────────────┤          │              │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│            │ CVE-2019-1010023 │          │              │                   │                  │ glibc: running ldd on malicious ELF leads to code execution │
│            │                  │          │              │                   │                  │ because of...                                               │
│            │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2019-1010023                │
│            ├──────────────────┤          │              │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│            │ CVE-2019-1010024 │          │              │                   │                  │ glibc: ASLR bypass using cache of thread stack and heap     │
│            │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2019-1010024                │
│            ├──────────────────┤          │              │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│            │ CVE-2019-1010025 │          │              │                   │                  │ glibc: information disclosure of heap addresses of          │
│            │                  │          │              │                   │                  │ pthread_created thread                                      │
│            │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2019-1010025                │
│            ├──────────────────┤          │              │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│            │ CVE-2019-9192    │          │              │                   │                  │ glibc: uncontrolled recursion in function                   │
│            │                  │          │              │                   │                  │ check_dst_limits_calc_pos_1 in posix/regexec.c              │
│            │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2019-9192                   │
├────────────┼──────────────────┤          │              ├───────────────────┼──────────────────┼─────────────────────────────────────────────────────────────┤
│ libgcc-s1  │ CVE-2023-4039    │          │              │ 10.2.1-6          │                  │ gcc: -fstack-protector fails to guard dynamic stack         │
│            │                  │          │              │                   │                  │ allocations on ARM64                                        │
│            │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-4039                   │
├────────────┤                  │          │              │                   ├──────────────────┤                                                             │
│ libgomp1   │                  │          │              │                   │                  │                                                             │
│            │                  │          │              │                   │                  │                                                             │
│            │                  │          │              │                   │                  │                                                             │
├────────────┼──────────────────┼──────────┼──────────────┼───────────────────┼──────────────────┼─────────────────────────────────────────────────────────────┤
│ libssl1.1  │ CVE-2023-5678    │ MEDIUM   │ fixed        │ 1.1.1w-0+deb11u1  │ 1.1.1w-0+deb11u2 │ openssl: Generating excessively long X9.42 DH keys or       │
│            │                  │          │              │                   │                  │ checking excessively long X9.42...                          │
│            │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-5678                   │
│            ├──────────────────┤          │              │                   │                  ├─────────────────────────────────────────────────────────────┤
│            │ CVE-2024-0727    │          │              │                   │                  │ openssl: denial of service via null dereference             │
│            │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-0727                   │
│            ├──────────────────┤          │              │                   │                  ├─────────────────────────────────────────────────────────────┤
│            │ CVE-2024-4741    │          │              │                   │                  │ openssl: Use After Free with SSL_free_buffers               │
│            │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-4741                   │
│            ├──────────────────┤          │              │                   │                  ├─────────────────────────────────────────────────────────────┤
│            │ CVE-2024-5535    │          │              │                   │                  │ openssl: SSL_select_next_proto buffer overread              │
│            │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-5535                   │
│            ├──────────────────┼──────────┤              │                   │                  ├─────────────────────────────────────────────────────────────┤
│            │ CVE-2024-2511    │ LOW      │              │                   │                  │ openssl: Unbounded memory growth with session handling in   │
│            │                  │          │              │                   │                  │ TLSv1.3                                                     │
│            │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-2511                   │
│            ├──────────────────┤          │              │                   │                  ├─────────────────────────────────────────────────────────────┤
│            │ CVE-2024-9143    │          │              │                   │                  │ openssl: Low-level invalid GF(2^m) parameters lead to OOB   │
│            │                  │          │              │                   │                  │ memory access                                               │
│            │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-9143                   │
├────────────┼──────────────────┤          ├──────────────┼───────────────────┼──────────────────┼─────────────────────────────────────────────────────────────┤
│ libstdc++6 │ CVE-2023-4039    │          │ affected     │ 10.2.1-6          │                  │ gcc: -fstack-protector fails to guard dynamic stack         │
│            │                  │          │              │                   │                  │ allocations on ARM64                                        │
│            │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-4039                   │
├────────────┼──────────────────┼──────────┼──────────────┼───────────────────┼──────────────────┼─────────────────────────────────────────────────────────────┤
│ openssl    │ CVE-2023-5678    │ MEDIUM   │ fixed        │ 1.1.1w-0+deb11u1  │ 1.1.1w-0+deb11u2 │ openssl: Generating excessively long X9.42 DH keys or       │
│            │                  │          │              │                   │                  │ checking excessively long X9.42...                          │
│            │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-5678                   │
│            ├──────────────────┤          │              │                   │                  ├─────────────────────────────────────────────────────────────┤
│            │ CVE-2024-0727    │          │              │                   │                  │ openssl: denial of service via null dereference             │
│            │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-0727                   │
│            ├──────────────────┤          │              │                   │                  ├─────────────────────────────────────────────────────────────┤
│            │ CVE-2024-4741    │          │              │                   │                  │ openssl: Use After Free with SSL_free_buffers               │
│            │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-4741                   │
│            ├──────────────────┤          │              │                   │                  ├─────────────────────────────────────────────────────────────┤
│            │ CVE-2024-5535    │          │              │                   │                  │ openssl: SSL_select_next_proto buffer overread              │
│            │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-5535                   │
│            ├──────────────────┼──────────┤              │                   │                  ├─────────────────────────────────────────────────────────────┤
│            │ CVE-2024-2511    │ LOW      │              │                   │                  │ openssl: Unbounded memory growth with session handling in   │
│            │                  │          │              │                   │                  │ TLSv1.3                                                     │
│            │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-2511                   │
│            ├──────────────────┤          │              │                   │                  ├─────────────────────────────────────────────────────────────┤
│            │ CVE-2024-9143    │          │              │                   │                  │ openssl: Low-level invalid GF(2^m) parameters lead to OOB   │
│            │                  │          │              │                   │                  │ memory access                                               │
│            │                  │          │              │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-9143                   │
├────────────┼──────────────────┼──────────┤              ├───────────────────┼──────────────────┼─────────────────────────────────────────────────────────────┤
│ tzdata     │ DLA-3972-1       │ UNKNOWN  │              │ 2024a-0+deb11u1   │ 2024b-0+deb11u1  │ tzdata - new timezone database                              │
└────────────┴──────────────────┴──────────┴──────────────┴───────────────────┴──────────────────┴─────────────────────────────────────────────────────────────┘

namespace: secops, deployment: juice-shop (node-pkg)
====================================================
Total: 55 (UNKNOWN: 0, LOW: 2, MEDIUM: 25, HIGH: 18, CRITICAL: 10)

┌─────────────────────────────────────┬─────────────────────┬──────────┬──────────┬───────────────────┬──────────────────────────────┬──────────────────────────────────────────────────────────────┐
│               Library               │    Vulnerability    │ Severity │  Status  │ Installed Version │        Fixed Version         │                            Title                             │
├─────────────────────────────────────┼─────────────────────┼──────────┼──────────┼───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ base64url (package.json)            │ NSWG-ECO-428        │ HIGH     │ fixed    │ 0.0.6             │ >=3.0.0                      │ Out-of-bounds Read                                           │
│                                     │                     │          │          │                   │                              │ https://hackerone.com/reports/321687                         │
│                                     ├─────────────────────┼──────────┤          │                   ├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ GHSA-rvg8-pwq2-xj7q │ MEDIUM   │          │                   │ 3.0.0                        │ Out-of-bounds Read in base64url                              │
│                                     │                     │          │          │                   │                              │ https://github.com/advisories/GHSA-rvg8-pwq2-xj7q            │
├─────────────────────────────────────┼─────────────────────┼──────────┤          ├───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ braces (package.json)               │ CVE-2024-4068       │ HIGH     │          │ 2.3.2             │ 3.0.3                        │ braces: fails to limit the number of characters it can       │
│                                     │                     │          │          │                   │                              │ handle                                                       │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2024-4068                    │
├─────────────────────────────────────┼─────────────────────┼──────────┤          ├───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ cookie (package.json)               │ CVE-2024-47764      │ LOW      │          │ 0.4.2             │ 0.7.0                        │ cookie: cookie accepts cookie name, path, and domain with    │
│                                     │                     │          │          │                   │                              │ out of bounds...                                             │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2024-47764                   │
├─────────────────────────────────────┼─────────────────────┼──────────┤          ├───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ cross-spawn (package.json)          │ CVE-2024-21538      │ HIGH     │          │ 7.0.3             │ 7.0.5, 6.0.6                 │ cross-spawn: regular expression denial of service            │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2024-21538                   │
├─────────────────────────────────────┼─────────────────────┼──────────┤          ├───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ crypto-js (package.json)            │ CVE-2023-46233      │ CRITICAL │          │ 3.3.0             │ 4.2.0                        │ crypto-js: PBKDF2 1,000 times weaker than specified in 1993  │
│                                     │                     │          │          │                   │                              │ and 1.3M times...                                            │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2023-46233                   │
├─────────────────────────────────────┼─────────────────────┼──────────┤          ├───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ engine.io (package.json)            │ CVE-2022-41940      │ MEDIUM   │          │ 4.1.2             │ 3.6.1, 6.2.1                 │ engine.io: Specially crafted HTTP request can trigger an     │
│                                     │                     │          │          │                   │                              │ uncaught exception                                           │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2022-41940                   │
├─────────────────────────────────────┼─────────────────────┼──────────┤          ├───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ express-jwt (package.json)          │ CVE-2020-15084      │ HIGH     │          │ 0.1.3             │ 6.0.0                        │ Authorization bypass in express-jwt                          │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2020-15084                   │
├─────────────────────────────────────┼─────────────────────┼──────────┤          ├───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ got (package.json)                  │ CVE-2022-33987      │ MEDIUM   │          │ 8.3.2             │ 12.1.0, 11.8.5               │ nodejs-got: missing verification of requested URLs allows    │
│                                     │                     │          │          │                   │                              │ redirects to UNIX sockets                                    │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2022-33987                   │
├─────────────────────────────────────┼─────────────────────┼──────────┤          ├───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ http-cache-semantics (package.json) │ CVE-2022-25881      │ HIGH     │          │ 3.8.1             │ 4.1.1                        │ http-cache-semantics: Regular Expression Denial of Service   │
│                                     │                     │          │          │                   │                              │ (ReDoS) vulnerability                                        │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2022-25881                   │
├─────────────────────────────────────┼─────────────────────┤          ├──────────┼───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ ip (package.json)                   │ CVE-2024-29415      │          │ affected │ 2.0.1             │                              │ node-ip: Incomplete fix for CVE-2023-42282                   │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2024-29415                   │
├─────────────────────────────────────┼─────────────────────┼──────────┼──────────┼───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ jsonwebtoken (package.json)         │ CVE-2015-9235       │ CRITICAL │ fixed    │ 0.1.0             │ 4.2.2                        │ nodejs-jsonwebtoken: verification step bypass with an        │
│                                     │                     │          │          │                   │                              │ altered token                                                │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2015-9235                    │
│                                     ├─────────────────────┼──────────┤          │                   ├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2022-23539      │ HIGH     │          │                   │ 9.0.0                        │ jsonwebtoken: Unrestricted key type could lead to legacy     │
│                                     │                     │          │          │                   │                              │ keys usagen                                                  │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2022-23539                   │
│                                     ├─────────────────────┤          │          │                   ├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ NSWG-ECO-17         │          │          │                   │ >=4.2.2                      │ Verification Bypass                                          │
│                                     ├─────────────────────┼──────────┤          │                   ├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2022-23540      │ MEDIUM   │          │                   │ 9.0.0                        │ jsonwebtoken: Insecure default algorithm in jwt.verify()     │
│                                     │                     │          │          │                   │                              │ could lead to signature validation bypass...                 │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2022-23540                   │
│                                     ├─────────────────────┤          │          │                   │                              ├──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2022-23541      │          │          │                   │                              │ jsonwebtoken: Insecure implementation of key retrieval       │
│                                     │                     │          │          │                   │                              │ function could lead to Forgeable Public/Private...           │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2022-23541                   │
│                                     ├─────────────────────┼──────────┤          ├───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2015-9235       │ CRITICAL │          │ 0.4.0             │ 4.2.2                        │ nodejs-jsonwebtoken: verification step bypass with an        │
│                                     │                     │          │          │                   │                              │ altered token                                                │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2015-9235                    │
│                                     ├─────────────────────┼──────────┤          │                   ├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2022-23539      │ HIGH     │          │                   │ 9.0.0                        │ jsonwebtoken: Unrestricted key type could lead to legacy     │
│                                     │                     │          │          │                   │                              │ keys usagen                                                  │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2022-23539                   │
│                                     ├─────────────────────┤          │          │                   ├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ NSWG-ECO-17         │          │          │                   │ >=4.2.2                      │ Verification Bypass                                          │
│                                     ├─────────────────────┼──────────┤          │                   ├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2022-23540      │ MEDIUM   │          │                   │ 9.0.0                        │ jsonwebtoken: Insecure default algorithm in jwt.verify()     │
│                                     │                     │          │          │                   │                              │ could lead to signature validation bypass...                 │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2022-23540                   │
│                                     ├─────────────────────┤          │          │                   │                              ├──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2022-23541      │          │          │                   │                              │ jsonwebtoken: Insecure implementation of key retrieval       │
│                                     │                     │          │          │                   │                              │ function could lead to Forgeable Public/Private...           │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2022-23541                   │
├─────────────────────────────────────┼─────────────────────┼──────────┤          ├───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ jws (package.json)                  │ CVE-2016-1000223    │ HIGH     │          │ 0.2.6             │ >=3.0.0                      │ Forgeable Public/Private Tokens                              │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2016-1000223                 │
├─────────────────────────────────────┼─────────────────────┼──────────┼──────────┼───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ libxmljs (package.json)             │ CVE-2024-34391      │ CRITICAL │ affected │ 1.0.11            │                              │ libxmljs vulnerable to type confusion when parsing specially │
│                                     │                     │          │          │                   │                              │ crafted XML                                                  │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2024-34391                   │
│                                     ├─────────────────────┤          │          │                   ├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2024-34392      │          │          │                   │                              │ libxmljs vulnerable to type confusion when parsing specially │
│                                     │                     │          │          │                   │                              │ crafted XML                                                  │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2024-34392                   │
├─────────────────────────────────────┼─────────────────────┤          ├──────────┼───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ lodash (package.json)               │ CVE-2019-10744      │          │ fixed    │ 2.4.2             │ 4.17.12                      │ nodejs-lodash: prototype pollution in defaultsDeep function  │
│                                     │                     │          │          │                   │                              │ leading to modifying properties                              │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2019-10744                   │
│                                     ├─────────────────────┼──────────┤          │                   ├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2018-16487      │ HIGH     │          │                   │ >=4.17.11                    │ lodash: Prototype pollution in utilities function            │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2018-16487                   │
│                                     ├─────────────────────┤          │          │                   ├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2021-23337      │          │          │                   │ 4.17.21                      │ nodejs-lodash: command injection via template                │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2021-23337                   │
│                                     ├─────────────────────┼──────────┤          │                   ├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2019-1010266    │ MEDIUM   │          │                   │ 4.17.11                      │ lodash: uncontrolled resource consumption in Data handler    │
│                                     │                     │          │          │                   │                              │ causing denial of service                                    │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2019-1010266                 │
│                                     ├─────────────────────┤          │          │                   ├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2020-28500      │          │          │                   │ 4.17.21                      │ nodejs-lodash: ReDoS via the toNumber, trim and trimEnd      │
│                                     │                     │          │          │                   │                              │ functions                                                    │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2020-28500                   │
│                                     ├─────────────────────┼──────────┤          │                   ├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2018-3721       │ LOW      │          │                   │ >=4.17.5                     │ lodash: Prototype pollution in utilities function            │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2018-3721                    │
├─────────────────────────────────────┼─────────────────────┼──────────┼──────────┼───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ lodash.set (package.json)           │ CVE-2020-8203       │ HIGH     │ affected │ 4.3.2             │                              │ nodejs-lodash: prototype pollution in zipObjectDeep function │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2020-8203                    │
├─────────────────────────────────────┼─────────────────────┼──────────┤          ├───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ marsdb (package.json)               │ GHSA-5mrr-rgp6-x4gr │ CRITICAL │          │ 0.6.11            │                              │ Command Injection in marsdb                                  │
│                                     │                     │          │          │                   │                              │ https://github.com/advisories/GHSA-5mrr-rgp6-x4gr            │
├─────────────────────────────────────┼─────────────────────┼──────────┼──────────┼───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ micromatch (package.json)           │ CVE-2024-4067       │ MEDIUM   │ fixed    │ 3.1.10            │ 4.0.8                        │ micromatch: vulnerable to Regular Expression Denial of       │
│                                     │                     │          │          │                   │                              │ Service                                                      │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2024-4067                    │
├─────────────────────────────────────┼─────────────────────┼──────────┤          ├───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ moment (package.json)               │ CVE-2017-18214      │ HIGH     │          │ 2.0.0             │ 2.19.3                       │ nodejs-moment: Regular expression denial of service          │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2017-18214                   │
│                                     ├─────────────────────┤          │          │                   ├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2022-24785      │          │          │                   │ 2.29.2                       │ Moment.js: Path traversal in moment.locale                   │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2022-24785                   │
│                                     ├─────────────────────┼──────────┤          │                   ├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2016-4055       │ MEDIUM   │          │                   │ >=2.11.2                     │ moment.js: regular expression denial of service              │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2016-4055                    │
├─────────────────────────────────────┼─────────────────────┤          ├──────────┼───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ notevil (package.json)              │ CVE-2021-23771      │          │ affected │ 1.3.3             │                              │ Sandbox escape in notevil and argencoders-notevil            │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2021-23771                   │
├─────────────────────────────────────┼─────────────────────┤          ├──────────┼───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ path-to-regexp (package.json)       │ CVE-2024-52798      │          │ fixed    │ 0.1.10            │ 0.1.12                       │ path-to-regexp: path-to-regexp Unpatched `path-to-regexp`    │
│                                     │                     │          │          │                   │                              │ ReDoS in 0.1.x                                               │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2024-52798                   │
├─────────────────────────────────────┼─────────────────────┤          ├──────────┼───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ request (package.json)              │ CVE-2023-28155      │          │ affected │ 2.88.2            │                              │ The Request package through 2.88.1 for Node.js allows a      │
│                                     │                     │          │          │                   │                              │ bypass of SSRF...                                            │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2023-28155                   │
├─────────────────────────────────────┼─────────────────────┼──────────┼──────────┼───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ sanitize-html (package.json)        │ CVE-2022-25887      │ HIGH     │ fixed    │ 1.4.2             │ 2.7.1                        │ sanitize-html: insecure global regular expression            │
│                                     │                     │          │          │                   │                              │ replacement logic may lead to ReDoS                          │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2022-25887                   │
│                                     ├─────────────────────┼──────────┤          │                   ├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2016-1000237    │ MEDIUM   │          │                   │ >=1.4.3                      │ XSS - Sanitization not applied recursively                   │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2016-1000237                 │
│                                     ├─────────────────────┤          │          │                   ├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2017-16016      │          │          │                   │ 1.11.4                       │ Cross-Site Scripting in sanitize-html                        │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2017-16016                   │
│                                     ├─────────────────────┤          │          │                   ├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2021-26539      │          │          │                   │ 2.3.1                        │ sanitize-html: improper handling of internationalized domain │
│                                     │                     │          │          │                   │                              │ name (IDN) can lead to bypass...                             │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2021-26539                   │
│                                     ├─────────────────────┤          │          │                   ├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2021-26540      │          │          │                   │ 2.3.2                        │ sanitize-html: improper validation of hostnames set by the   │
│                                     │                     │          │          │                   │                              │ "allowedIframeHostnames" option can lead...                  │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2021-26540                   │
│                                     ├─────────────────────┤          │          │                   ├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2024-21501      │          │          │                   │ 2.12.1                       │ sanitize-html: Information Exposure when used on the backend │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2024-21501                   │
│                                     ├─────────────────────┤          │          │                   ├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ NSWG-ECO-154        │          │          │                   │ >=1.11.4                     │ Cross Site Scripting                                         │
├─────────────────────────────────────┼─────────────────────┤          │          ├───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ socket.io (package.json)            │ CVE-2024-38355      │          │          │ 3.1.2             │ 2.5.1, 4.6.2                 │ socket.io: Unhandled 'error' event                           │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2024-38355                   │
├─────────────────────────────────────┼─────────────────────┤          │          ├───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ socket.io-parser (package.json)     │ CVE-2023-32695      │          │          │ 4.0.5             │ 4.2.3, 3.4.3, 3.3.4          │ socket.io parser is a socket.io encoder and decoder written  │
│                                     │                     │          │          │                   │                              │ in JavaScr ......                                            │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2023-32695                   │
├─────────────────────────────────────┼─────────────────────┤          │          ├───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ tar (package.json)                  │ CVE-2024-28863      │          │          │ 4.4.19            │ 6.2.1                        │ node-tar: denial of service while parsing a tar file due to  │
│                                     │                     │          │          │                   │                              │ lack...                                                      │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2024-28863                   │
├─────────────────────────────────────┼─────────────────────┤          │          ├───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ tough-cookie (package.json)         │ CVE-2023-26136      │          │          │ 2.5.0             │ 4.1.3                        │ tough-cookie: prototype pollution in cookie memstore         │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2023-26136                   │
├─────────────────────────────────────┼─────────────────────┼──────────┤          ├───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ vm2 (package.json)                  │ CVE-2023-32314      │ CRITICAL │          │ 3.9.17            │ 3.9.18                       │ vm2: Sandbox Escape                                          │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2023-32314                   │
│                                     ├─────────────────────┤          ├──────────┤                   ├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2023-37466      │          │ affected │                   │                              │ vm2: Promise handler sanitization can be bypassed allowing   │
│                                     │                     │          │          │                   │                              │ attackers to escape the...                                   │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2023-37466                   │
│                                     ├─────────────────────┤          │          │                   ├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2023-37903      │          │          │                   │                              │ vm2: custom inspect function allows attackers to escape the  │
│                                     │                     │          │          │                   │                              │ sandbox and run...                                           │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2023-37903                   │
│                                     ├─────────────────────┼──────────┼──────────┤                   ├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2023-32313      │ MEDIUM   │ fixed    │                   │ 3.9.18                       │ vm2: Inspect Manipulation                                    │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2023-32313                   │
├─────────────────────────────────────┼─────────────────────┼──────────┤          ├───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ ws (package.json)                   │ CVE-2024-37890      │ HIGH     │          │ 7.4.6             │ 5.2.4, 6.2.3, 7.5.10, 8.17.1 │ nodejs-ws: denial of service when handling a request with    │
│                                     │                     │          │          │                   │                              │ many HTTP headers...                                         │
│                                     │                     │          │          │                   │                              │ https://avd.aquasec.com/nvd/cve-2024-37890                   │
└─────────────────────────────────────┴─────────────────────┴──────────┴──────────┴───────────────────┴──────────────────────────────┴──────────────────────────────────────────────────────────────┘

namespace: secops, deployment: juice-shop (secrets)
===================================================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

HIGH: AsymmetricPrivateKey (private-key)
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Asymmetric Private Key
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: juice-shop:47 (added by 'COPY --chown=65532:0 /juice-shop . # bui')
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  45   const z85 = __importStar(require("z85"));
  46   exports.publicKey = fs_1.default ? fs_1.default.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'pl
  47 [ ----BEGIN RSA PRIVATE KEY-----****************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************-----END RSA PRIVATE
  48   const hash = (data) => crypto_1.default.createHash('md5').update(data).digest('hex');
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────



namespace: secops, deployment: juice-shop (secrets)
===================================================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 0)

MEDIUM: JWT (jwt-token)
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
JWT token
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: juice-shop:40 (added by 'COPY --chown=65532:0 /juice-shop . # bui')
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  38   
  39     it('returns payload from decoding a valid JWT', inject([LoginGuard], (guard: LoginGuard) => {
  40 [ ocalStorage.setItem('token', '***********************************************************************************************************************************************************')
  41       expect(guard.tokenDecode()).toEqual({
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────



namespace: secops, deployment: juice-shop (secrets)
===================================================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 0)

MEDIUM: JWT (jwt-token)
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
JWT token
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: juice-shop:50 (added by 'COPY --chown=65532:0 /juice-shop . # bui')
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  48   
  49     xit('should set Last-Login IP from JWT as trusted HTML', () => { // FIXME Expected state seems to 
  50 [ ocalStorage.setItem('token', '*******************************************************************************************************************************')
  51       component.ngOnInit()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────



namespace: secops, deployment: juice-shop (secrets)
===================================================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

HIGH: AsymmetricPrivateKey (private-key)
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Asymmetric Private Key
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: juice-shop:23 (added by 'COPY --chown=65532:0 /juice-shop . # bui')
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  21   
  22   export const publicKey = fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'placeholder-publi
  23 [ ----BEGIN RSA PRIVATE KEY-----****************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************-----END RSA PRIVATE
  24   
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────



namespace: secops, cronjob: kube-hunter
=======================================
Total: 33 (UNKNOWN: 0, LOW: 0, MEDIUM: 14, HIGH: 18, CRITICAL: 1)

┌───────────────────────┬────────────────┬──────────┬────────┬───────────────────┬──────────────────┬─────────────────────────────────────────────────────────────┐
│        Library        │ Vulnerability  │ Severity │ Status │ Installed Version │  Fixed Version   │                            Title                            │
├───────────────────────┼────────────────┼──────────┼────────┼───────────────────┼──────────────────┼─────────────────────────────────────────────────────────────┤
│ expat                 │ CVE-2022-40674 │ HIGH     │ fixed  │ 2.4.7-r0          │ 2.4.9-r0         │ expat: a use-after-free in the doContent function in        │
│                       │                │          │        │                   │                  │ xmlparse.c                                                  │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-40674                  │
│                       ├────────────────┤          │        │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2022-43680 │          │        │                   │ 2.5.0-r0         │ expat: use-after free caused by overeager destruction of a  │
│                       │                │          │        │                   │                  │ shared DTD in...                                            │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-43680                  │
├───────────────────────┼────────────────┤          │        ├───────────────────┼──────────────────┼─────────────────────────────────────────────────────────────┤
│ krb5-libs             │ CVE-2022-42898 │          │        │ 1.19.3-r0         │ 1.19.4-r0        │ krb5: integer overflow vulnerabilities in PAC parsing       │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-42898                  │
├───────────────────────┼────────────────┤          │        ├───────────────────┼──────────────────┼─────────────────────────────────────────────────────────────┤
│ libcom_err            │ CVE-2022-1304  │          │        │ 1.46.4-r0         │ 1.46.6-r0        │ e2fsprogs: out-of-bounds read/write via crafted filesystem  │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-1304                   │
├───────────────────────┼────────────────┤          │        ├───────────────────┼──────────────────┼─────────────────────────────────────────────────────────────┤
│ libcrypto1.1          │ CVE-2022-4450  │          │        │ 1.1.1n-r0         │ 1.1.1t-r0        │ openssl: double free after calling PEM_read_bio_ex          │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-4450                   │
│                       ├────────────────┤          │        │                   │                  ├─────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-0215  │          │        │                   │                  │ openssl: use-after-free following BIO_new_NDEF              │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-0215                   │
│                       ├────────────────┤          │        │                   │                  ├─────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-0286  │          │        │                   │                  │ openssl: X.400 address type confusion in X.509 GeneralName  │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-0286                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-0464  │          │        │                   │ 1.1.1t-r2        │ openssl: Denial of service by excessive resource usage in   │
│                       │                │          │        │                   │                  │ verifying X509 policy...                                    │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-0464                   │
│                       ├────────────────┼──────────┤        │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2022-2097  │ MEDIUM   │        │                   │ 1.1.1q-r0        │ openssl: AES OCB fails to encrypt some bytes                │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-2097                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2022-4304  │          │        │                   │ 1.1.1t-r0        │ openssl: timing attack in RSA Decryption implementation     │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-4304                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-0465  │          │        │                   │ 1.1.1t-r2        │ openssl: Invalid certificate policies in leaf certificates  │
│                       │                │          │        │                   │                  │ are silently ignored                                        │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-0465                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-2650  │          │        │                   │ 1.1.1u-r0        │ openssl: Possible DoS translating ASN.1 object identifiers  │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-2650                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-3446  │          │        │                   │ 1.1.1u-r2        │ openssl: Excessive time spent checking DH keys and          │
│                       │                │          │        │                   │                  │ parameters                                                  │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-3446                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-3817  │          │        │                   │ 1.1.1v-r0        │ OpenSSL: Excessive time spent checking DH q parameter value │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-3817                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-5678  │          │        │                   │ 1.1.1w-r1        │ openssl: Generating excessively long X9.42 DH keys or       │
│                       │                │          │        │                   │                  │ checking excessively long X9.42...                          │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-5678                   │
├───────────────────────┼────────────────┼──────────┤        │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│ libssl1.1             │ CVE-2022-4450  │ HIGH     │        │                   │ 1.1.1t-r0        │ openssl: double free after calling PEM_read_bio_ex          │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-4450                   │
│                       ├────────────────┤          │        │                   │                  ├─────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-0215  │          │        │                   │                  │ openssl: use-after-free following BIO_new_NDEF              │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-0215                   │
│                       ├────────────────┤          │        │                   │                  ├─────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-0286  │          │        │                   │                  │ openssl: X.400 address type confusion in X.509 GeneralName  │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-0286                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-0464  │          │        │                   │ 1.1.1t-r2        │ openssl: Denial of service by excessive resource usage in   │
│                       │                │          │        │                   │                  │ verifying X509 policy...                                    │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-0464                   │
│                       ├────────────────┼──────────┤        │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2022-2097  │ MEDIUM   │        │                   │ 1.1.1q-r0        │ openssl: AES OCB fails to encrypt some bytes                │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-2097                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2022-4304  │          │        │                   │ 1.1.1t-r0        │ openssl: timing attack in RSA Decryption implementation     │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-4304                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-0465  │          │        │                   │ 1.1.1t-r2        │ openssl: Invalid certificate policies in leaf certificates  │
│                       │                │          │        │                   │                  │ are silently ignored                                        │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-0465                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-2650  │          │        │                   │ 1.1.1u-r0        │ openssl: Possible DoS translating ASN.1 object identifiers  │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-2650                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-3446  │          │        │                   │ 1.1.1u-r2        │ openssl: Excessive time spent checking DH keys and          │
│                       │                │          │        │                   │                  │ parameters                                                  │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-3446                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-3817  │          │        │                   │ 1.1.1v-r0        │ OpenSSL: Excessive time spent checking DH q parameter value │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-3817                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-5678  │          │        │                   │ 1.1.1w-r1        │ openssl: Generating excessively long X9.42 DH keys or       │
│                       │                │          │        │                   │                  │ checking excessively long X9.42...                          │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-5678                   │
├───────────────────────┼────────────────┼──────────┤        ├───────────────────┼──────────────────┼─────────────────────────────────────────────────────────────┤
│ libtirpc              │ CVE-2021-46828 │ HIGH     │        │ 1.3.2-r0          │ 1.3.2-r1         │ libtirpc: DoS vulnerability with lots of connections        │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2021-46828                  │
├───────────────────────┤                │          │        │                   │                  │                                                             │
│ libtirpc-conf         │                │          │        │                   │                  │                                                             │
│                       │                │          │        │                   │                  │                                                             │
├───────────────────────┼────────────────┤          │        ├───────────────────┼──────────────────┼─────────────────────────────────────────────────────────────┤
│ ncurses-libs          │ CVE-2022-29458 │          │        │ 6.3_p20211120-r0  │ 6.3_p20211120-r1 │ ncurses: segfaulting OOB read                               │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-29458                  │
│                       ├────────────────┤          │        │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-29491 │          │        │                   │ 6.3_p20211120-r2 │ ncurses: Local users can trigger security-relevant memory   │
│                       │                │          │        │                   │                  │ corruption via malformed data                               │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-29491                  │
├───────────────────────┼────────────────┤          │        │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│ ncurses-terminfo-base │ CVE-2022-29458 │          │        │                   │ 6.3_p20211120-r1 │ ncurses: segfaulting OOB read                               │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-29458                  │
│                       ├────────────────┤          │        │                   ├──────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-29491 │          │        │                   │ 6.3_p20211120-r2 │ ncurses: Local users can trigger security-relevant memory   │
│                       │                │          │        │                   │                  │ corruption via malformed data                               │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-29491                  │
├───────────────────────┼────────────────┼──────────┤        ├───────────────────┼──────────────────┼─────────────────────────────────────────────────────────────┤
│ zlib                  │ CVE-2022-37434 │ CRITICAL │        │ 1.2.12-r1         │ 1.2.12-r2        │ zlib: heap-based buffer over-read and overflow in inflate() │
│                       │                │          │        │                   │                  │ in inflate.c via a...                                       │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2022-37434                  │
└───────────────────────┴────────────────┴──────────┴────────┴───────────────────┴──────────────────┴─────────────────────────────────────────────────────────────┘

namespace: secops, cronjob: kube-hunter (python-pkg)
====================================================
Total: 15 (UNKNOWN: 0, LOW: 1, MEDIUM: 8, HIGH: 6, CRITICAL: 0)

┌───────────────────────┬────────────────┬──────────┬────────┬───────────────────┬────────────────┬─────────────────────────────────────────────────────────────┐
│        Library        │ Vulnerability  │ Severity │ Status │ Installed Version │ Fixed Version  │                            Title                            │
├───────────────────────┼────────────────┼──────────┼────────┼───────────────────┼────────────────┼─────────────────────────────────────────────────────────────┤
│ certifi (METADATA)    │ CVE-2023-37920 │ HIGH     │ fixed  │ 2021.10.8         │ 2023.7.22      │ python-certifi: Removal of e-Tugra root certificate         │
│                       │                │          │        │                   │                │ https://avd.aquasec.com/nvd/cve-2023-37920                  │
│                       ├────────────────┼──────────┤        │                   ├────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2022-23491 │ MEDIUM   │        │                   │ 2022.12.07     │ python-certifi: untrusted root certificates                 │
│                       │                │          │        │                   │                │ https://avd.aquasec.com/nvd/cve-2022-23491                  │
│                       ├────────────────┼──────────┤        │                   ├────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-39689 │ LOW      │        │                   │ 2024.07.04     │ python-certifi: Remove root certificates from `GLOBALTRUST` │
│                       │                │          │        │                   │                │ from the root store                                         │
│                       │                │          │        │                   │                │ https://avd.aquasec.com/nvd/cve-2024-39689                  │
├───────────────────────┼────────────────┼──────────┤        ├───────────────────┼────────────────┼─────────────────────────────────────────────────────────────┤
│ future (METADATA)     │ CVE-2022-40899 │ HIGH     │        │ 0.18.2            │ 0.18.3         │ python-future: remote attackers can cause denial of service │
│                       │                │          │        │                   │                │ via crafted Set-Cookie header...                            │
│                       │                │          │        │                   │                │ https://avd.aquasec.com/nvd/cve-2022-40899                  │
├───────────────────────┼────────────────┼──────────┤        ├───────────────────┼────────────────┼─────────────────────────────────────────────────────────────┤
│ idna (METADATA)       │ CVE-2024-3651  │ MEDIUM   │        │ 3.3               │ 3.7            │ python-idna: potential DoS via resource consumption via     │
│                       │                │          │        │                   │                │ specially crafted inputs to idna.encode()...                │
│                       │                │          │        │                   │                │ https://avd.aquasec.com/nvd/cve-2024-3651                   │
├───────────────────────┼────────────────┤          │        ├───────────────────┼────────────────┼─────────────────────────────────────────────────────────────┤
│ oauthlib (METADATA)   │ CVE-2022-36087 │          │        │ 3.2.0             │ 3.2.2          │ python-oauthlib: DoS when attacker provides malicious IPV6  │
│                       │                │          │        │                   │                │ URI                                                         │
│                       │                │          │        │                   │                │ https://avd.aquasec.com/nvd/cve-2022-36087                  │
├───────────────────────┼────────────────┤          │        ├───────────────────┼────────────────┼─────────────────────────────────────────────────────────────┤
│ pip (METADATA)        │ CVE-2023-5752  │          │        │ 22.0.4            │ 23.3           │ pip: Mercurial configuration injectable in repo revision    │
│                       │                │          │        │                   │                │ when installing via pip                                     │
│                       │                │          │        │                   │                │ https://avd.aquasec.com/nvd/cve-2023-5752                   │
├───────────────────────┼────────────────┤          │        ├───────────────────┼────────────────┼─────────────────────────────────────────────────────────────┤
│ requests (METADATA)   │ CVE-2023-32681 │          │        │ 2.27.1            │ 2.31.0         │ python-requests: Unintended leak of Proxy-Authorization     │
│                       │                │          │        │                   │                │ header                                                      │
│                       │                │          │        │                   │                │ https://avd.aquasec.com/nvd/cve-2023-32681                  │
│                       ├────────────────┤          │        │                   ├────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-35195 │          │        │                   │ 2.32.0         │ requests: subsequent requests to the same host ignore cert  │
│                       │                │          │        │                   │                │ verification                                                │
│                       │                │          │        │                   │                │ https://avd.aquasec.com/nvd/cve-2024-35195                  │
├───────────────────────┼────────────────┼──────────┤        ├───────────────────┼────────────────┼─────────────────────────────────────────────────────────────┤
│ setuptools (METADATA) │ CVE-2022-40897 │ HIGH     │        │ 57.5.0            │ 65.5.1         │ pypa-setuptools: Regular Expression Denial of Service       │
│                       │                │          │        │                   │                │ (ReDoS) in package_index.py                                 │
│                       │                │          │        │                   │                │ https://avd.aquasec.com/nvd/cve-2022-40897                  │
│                       ├────────────────┤          │        │                   ├────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-6345  │          │        │                   │ 70.0.0         │ pypa/setuptools: Remote code execution via download         │
│                       │                │          │        │                   │                │ functions in the package_index module in...                 │
│                       │                │          │        │                   │                │ https://avd.aquasec.com/nvd/cve-2024-6345                   │
├───────────────────────┼────────────────┤          │        ├───────────────────┼────────────────┼─────────────────────────────────────────────────────────────┤
│ urllib3 (METADATA)    │ CVE-2023-43804 │          │        │ 1.26.9            │ 2.0.6, 1.26.17 │ python-urllib3: Cookie request header isn't stripped during │
│                       │                │          │        │                   │                │ cross-origin redirects                                      │
│                       │                │          │        │                   │                │ https://avd.aquasec.com/nvd/cve-2023-43804                  │
│                       ├────────────────┼──────────┤        │                   ├────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-45803 │ MEDIUM   │        │                   │ 2.0.7, 1.26.18 │ urllib3: Request body not stripped after redirect from 303  │
│                       │                │          │        │                   │                │ status changes request...                                   │
│                       │                │          │        │                   │                │ https://avd.aquasec.com/nvd/cve-2023-45803                  │
│                       ├────────────────┤          │        │                   ├────────────────┼─────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-37891 │          │        │                   │ 1.26.19, 2.2.2 │ urllib3: proxy-authorization request header is not stripped │
│                       │                │          │        │                   │                │ during cross-origin redirects                               │
│                       │                │          │        │                   │                │ https://avd.aquasec.com/nvd/cve-2024-37891                  │
├───────────────────────┼────────────────┼──────────┤        ├───────────────────┼────────────────┼─────────────────────────────────────────────────────────────┤
│ wheel (METADATA)      │ CVE-2022-40898 │ HIGH     │        │ 0.37.1            │ 0.38.1         │ python-wheel: remote attackers can cause denial of service  │
│                       │                │          │        │                   │                │ via attacker controlled input...                            │
│                       │                │          │        │                   │                │ https://avd.aquasec.com/nvd/cve-2022-40898                  │
└───────────────────────┴────────────────┴──────────┴────────┴───────────────────┴────────────────┴─────────────────────────────────────────────────────────────┘

namespace: secops, cronjob: kube-bench
======================================
Total: 3 (UNKNOWN: 0, LOW: 3, MEDIUM: 0, HIGH: 0, CRITICAL: 0)

┌────────────┬───────────────┬──────────┬────────┬───────────────────┬───────────────┬───────────────────────────────────────────────────────────┐
│  Library   │ Vulnerability │ Severity │ Status │ Installed Version │ Fixed Version │                           Title                           │
├────────────┼───────────────┼──────────┼────────┼───────────────────┼───────────────┼───────────────────────────────────────────────────────────┤
│ libcrypto3 │ CVE-2024-9143 │ LOW      │ fixed  │ 3.3.2-r0          │ 3.3.2-r1      │ openssl: Low-level invalid GF(2^m) parameters lead to OOB │
│            │               │          │        │                   │               │ memory access                                             │
│            │               │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2024-9143                 │
├────────────┤               │          │        │                   │               │                                                           │
│ libssl3    │               │          │        │                   │               │                                                           │
│            │               │          │        │                   │               │                                                           │
│            │               │          │        │                   │               │                                                           │
├────────────┤               │          │        │                   │               │                                                           │
│ openssl    │               │          │        │                   │               │                                                           │
│            │               │          │        │                   │               │                                                           │
│            │               │          │        │                   │               │                                                           │
└────────────┴───────────────┴──────────┴────────┴───────────────────┴───────────────┴───────────────────────────────────────────────────────────┘

namespace: secops, cronjob: kube-bench (gobinary)
=================================================
Total: 2 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 1)

┌─────────────────────┬────────────────┬──────────┬────────┬───────────────────┬───────────────┬────────────────────────────────────────────────────────┐
│       Library       │ Vulnerability  │ Severity │ Status │ Installed Version │ Fixed Version │                         Title                          │
├─────────────────────┼────────────────┼──────────┼────────┼───────────────────┼───────────────┼────────────────────────────────────────────────────────┤
│ golang.org/x/crypto │ CVE-2024-45337 │ CRITICAL │ fixed  │ v0.21.0           │ 0.31.0        │ golang.org/x/crypto/ssh: Misuse of                     │
│                     │                │          │        │                   │               │ ServerConfig.PublicKeyCallback may cause authorization │
│                     │                │          │        │                   │               │ bypass in golang.org/x/crypto                          │
│                     │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2024-45337             │
├─────────────────────┼────────────────┼──────────┤        ├───────────────────┼───────────────┼────────────────────────────────────────────────────────┤
│ golang.org/x/net    │ CVE-2024-45338 │ HIGH     │        │ v0.23.0           │ 0.33.0        │ golang.org/x/net/html: Non-linear parsing of           │
│                     │                │          │        │                   │               │ case-insensitive content in golang.org/x/net/html      │
│                     │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2024-45338             │
└─────────────────────┴────────────────┴──────────┴────────┴───────────────────┴───────────────┴────────────────────────────────────────────────────────┘

namespace: secops, cronjob: kube-bench (gobinary)
=================================================
Total: 4 (UNKNOWN: 0, LOW: 0, MEDIUM: 2, HIGH: 2, CRITICAL: 0)

┌──────────────────┬────────────────┬──────────┬────────┬───────────────────┬────────────────┬─────────────────────────────────────────────────────────────┐
│     Library      │ Vulnerability  │ Severity │ Status │ Installed Version │ Fixed Version  │                            Title                            │
├──────────────────┼────────────────┼──────────┼────────┼───────────────────┼────────────────┼─────────────────────────────────────────────────────────────┤
│ golang.org/x/net │ CVE-2024-45338 │ HIGH     │ fixed  │ v0.26.0           │ 0.33.0         │ golang.org/x/net/html: Non-linear parsing of                │
│                  │                │          │        │                   │                │ case-insensitive content in golang.org/x/net/html           │
│                  │                │          │        │                   │                │ https://avd.aquasec.com/nvd/cve-2024-45338                  │
├──────────────────┼────────────────┤          │        ├───────────────────┼────────────────┼─────────────────────────────────────────────────────────────┤
│ stdlib           │ CVE-2024-34156 │          │        │ v1.22.5           │ 1.22.7, 1.23.1 │ encoding/gob: golang: Calling Decoder.Decode on a message   │
│                  │                │          │        │                   │                │ which contains deeply nested structures...                  │
│                  │                │          │        │                   │                │ https://avd.aquasec.com/nvd/cve-2024-34156                  │
│                  ├────────────────┼──────────┤        │                   │                ├─────────────────────────────────────────────────────────────┤
│                  │ CVE-2024-34155 │ MEDIUM   │        │                   │                │ go/parser: golang: Calling any of the Parse functions       │
│                  │                │          │        │                   │                │ containing deeply nested literals...                        │
│                  │                │          │        │                   │                │ https://avd.aquasec.com/nvd/cve-2024-34155                  │
│                  ├────────────────┤          │        │                   │                ├─────────────────────────────────────────────────────────────┤
│                  │ CVE-2024-34158 │          │        │                   │                │ go/build/constraint: golang: Calling Parse on a "// +build" │
│                  │                │          │        │                   │                │ build tag line with...                                      │
│                  │                │          │        │                   │                │ https://avd.aquasec.com/nvd/cve-2024-34158                  │
└──────────────────┴────────────────┴──────────┴────────┴───────────────────┴────────────────┴─────────────────────────────────────────────────────────────┘

namespace: secops, cronjob: kube-bench (kubernetes)
===================================================
Tests: 110 (SUCCESSES: 95, FAILURES: 15)
Failures: 15 (UNKNOWN: 0, LOW: 9, MEDIUM: 4, HIGH: 2, CRITICAL: 0)

AVD-KSV-0001 (MEDIUM): Container 'kube-bench' of CronJob 'kube-bench' should set 'securityContext.allowPrivilegeEscalation' to false
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node.

See https://avd.aquasec.com/misconfig/ksv001
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-bench:16-56
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌                         - command:
  17 │                             - kube-bench
  18 │                           image: docker.io/aquasec/kube-bench:v0.9.1
  19 │                           name: kube-bench
  20 │                           volumeMounts:
  21 │                             - mountPath: /var/lib/cni
  22 │                               name: var-lib-cni
  23 │                               readOnly: true
  24 └                             - mountPath: /var/lib/etcd
  ..   
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0003 (LOW): Container 'kube-bench' of CronJob 'kube-bench' should add 'ALL' to 'securityContext.capabilities.drop'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
The container should drop all default capabilities and add only those that are needed for its execution.

See https://avd.aquasec.com/misconfig/ksv003
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-bench:16-56
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌                         - command:
  17 │                             - kube-bench
  18 │                           image: docker.io/aquasec/kube-bench:v0.9.1
  19 │                           name: kube-bench
  20 │                           volumeMounts:
  21 │                             - mountPath: /var/lib/cni
  22 │                               name: var-lib-cni
  23 │                               readOnly: true
  24 └                             - mountPath: /var/lib/etcd
  ..   
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0010 (HIGH): CronJob 'kube-bench' should not set 'spec.template.spec.hostPID' to true
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Sharing the host’s PID namespace allows visibility on host processes, potentially leaking information such as environment variables and configuration.

See https://avd.aquasec.com/misconfig/ksv010
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-bench:8-96
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   8 ┌     jobTemplate:
   9 │         spec:
  10 │             template:
  11 │                 metadata:
  12 │                     labels:
  13 │                         app: kube-bench
  14 │                 spec:
  15 │                     containers:
  16 └                         - command:
  ..   
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0011 (LOW): Container 'kube-bench' of CronJob 'kube-bench' should set 'resources.limits.cpu'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Enforcing CPU limits prevents DoS via resource exhaustion.

See https://avd.aquasec.com/misconfig/ksv011
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-bench:16-56
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌                         - command:
  17 │                             - kube-bench
  18 │                           image: docker.io/aquasec/kube-bench:v0.9.1
  19 │                           name: kube-bench
  20 │                           volumeMounts:
  21 │                             - mountPath: /var/lib/cni
  22 │                               name: var-lib-cni
  23 │                               readOnly: true
  24 └                             - mountPath: /var/lib/etcd
  ..   
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0012 (MEDIUM): Container 'kube-bench' of CronJob 'kube-bench' should set 'securityContext.runAsNonRoot' to true
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Force the running image to run as a non-root user to ensure least privileges.

See https://avd.aquasec.com/misconfig/ksv012
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-bench:16-56
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌                         - command:
  17 │                             - kube-bench
  18 │                           image: docker.io/aquasec/kube-bench:v0.9.1
  19 │                           name: kube-bench
  20 │                           volumeMounts:
  21 │                             - mountPath: /var/lib/cni
  22 │                               name: var-lib-cni
  23 │                               readOnly: true
  24 └                             - mountPath: /var/lib/etcd
  ..   
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0014 (HIGH): Container 'kube-bench' of CronJob 'kube-bench' should set 'securityContext.readOnlyRootFilesystem' to true
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk.

See https://avd.aquasec.com/misconfig/ksv014
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-bench:16-56
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌                         - command:
  17 │                             - kube-bench
  18 │                           image: docker.io/aquasec/kube-bench:v0.9.1
  19 │                           name: kube-bench
  20 │                           volumeMounts:
  21 │                             - mountPath: /var/lib/cni
  22 │                               name: var-lib-cni
  23 │                               readOnly: true
  24 └                             - mountPath: /var/lib/etcd
  ..   
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0015 (LOW): Container 'kube-bench' of CronJob 'kube-bench' should set 'resources.requests.cpu'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
When containers have resource requests specified, the scheduler can make better decisions about which nodes to place pods on, and how to deal with resource contention.

See https://avd.aquasec.com/misconfig/ksv015
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-bench:16-56
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌                         - command:
  17 │                             - kube-bench
  18 │                           image: docker.io/aquasec/kube-bench:v0.9.1
  19 │                           name: kube-bench
  20 │                           volumeMounts:
  21 │                             - mountPath: /var/lib/cni
  22 │                               name: var-lib-cni
  23 │                               readOnly: true
  24 └                             - mountPath: /var/lib/etcd
  ..   
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0016 (LOW): Container 'kube-bench' of CronJob 'kube-bench' should set 'resources.requests.memory'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
When containers have memory requests specified, the scheduler can make better decisions about which nodes to place pods on, and how to deal with resource contention.

See https://avd.aquasec.com/misconfig/ksv016
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-bench:16-56
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌                         - command:
  17 │                             - kube-bench
  18 │                           image: docker.io/aquasec/kube-bench:v0.9.1
  19 │                           name: kube-bench
  20 │                           volumeMounts:
  21 │                             - mountPath: /var/lib/cni
  22 │                               name: var-lib-cni
  23 │                               readOnly: true
  24 └                             - mountPath: /var/lib/etcd
  ..   
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0018 (LOW): Container 'kube-bench' of CronJob 'kube-bench' should set 'resources.limits.memory'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Enforcing memory limits prevents DoS via resource exhaustion.

See https://avd.aquasec.com/misconfig/ksv018
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-bench:16-56
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌                         - command:
  17 │                             - kube-bench
  18 │                           image: docker.io/aquasec/kube-bench:v0.9.1
  19 │                           name: kube-bench
  20 │                           volumeMounts:
  21 │                             - mountPath: /var/lib/cni
  22 │                               name: var-lib-cni
  23 │                               readOnly: true
  24 └                             - mountPath: /var/lib/etcd
  ..   
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0020 (LOW): Container 'kube-bench' of CronJob 'kube-bench' should set 'securityContext.runAsUser' > 10000
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Force the container to run with user ID > 10000 to avoid conflicts with the host’s user table.

See https://avd.aquasec.com/misconfig/ksv020
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-bench:16-56
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌                         - command:
  17 │                             - kube-bench
  18 │                           image: docker.io/aquasec/kube-bench:v0.9.1
  19 │                           name: kube-bench
  20 │                           volumeMounts:
  21 │                             - mountPath: /var/lib/cni
  22 │                               name: var-lib-cni
  23 │                               readOnly: true
  24 └                             - mountPath: /var/lib/etcd
  ..   
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0021 (LOW): Container 'kube-bench' of CronJob 'kube-bench' should set 'securityContext.runAsGroup' > 10000
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Force the container to run with group ID > 10000 to avoid conflicts with the host’s user table.

See https://avd.aquasec.com/misconfig/ksv021
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-bench:16-56
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌                         - command:
  17 │                             - kube-bench
  18 │                           image: docker.io/aquasec/kube-bench:v0.9.1
  19 │                           name: kube-bench
  20 │                           volumeMounts:
  21 │                             - mountPath: /var/lib/cni
  22 │                               name: var-lib-cni
  23 │                               readOnly: true
  24 └                             - mountPath: /var/lib/etcd
  ..   
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0023 (MEDIUM): CronJob 'kube-bench' should not set 'spec.template.volumes.hostPath'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
According to pod security standard 'HostPath Volumes', HostPath volumes must be forbidden.

See https://avd.aquasec.com/misconfig/ksv023
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-bench:8-96
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   8 ┌     jobTemplate:
   9 │         spec:
  10 │             template:
  11 │                 metadata:
  12 │                     labels:
  13 │                         app: kube-bench
  14 │                 spec:
  15 │                     containers:
  16 └                         - command:
  ..   
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0030 (LOW): Either Pod or Container should set 'securityContext.seccompProfile.type' to 'RuntimeDefault'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
According to pod security standard 'Seccomp', the RuntimeDefault seccomp profile must be required, or allow specific additional profiles.

See https://avd.aquasec.com/misconfig/ksv030
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-bench:16-56
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌                         - command:
  17 │                             - kube-bench
  18 │                           image: docker.io/aquasec/kube-bench:v0.9.1
  19 │                           name: kube-bench
  20 │                           volumeMounts:
  21 │                             - mountPath: /var/lib/cni
  22 │                               name: var-lib-cni
  23 │                               readOnly: true
  24 └                             - mountPath: /var/lib/etcd
  ..   
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0104 (MEDIUM): container "kube-bench" of cronjob "kube-bench" in "secops" namespace should specify a seccomp profile
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
A program inside the container can bypass Seccomp protection policies.

See https://avd.aquasec.com/misconfig/ksv104
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0106 (LOW): container should drop all
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Containers must drop ALL capabilities, and are only permitted to add back the NET_BIND_SERVICE capability.

See https://avd.aquasec.com/misconfig/ksv106
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-bench:16-56
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌                         - command:
  17 │                             - kube-bench
  18 │                           image: docker.io/aquasec/kube-bench:v0.9.1
  19 │                           name: kube-bench
  20 │                           volumeMounts:
  21 │                             - mountPath: /var/lib/cni
  22 │                               name: var-lib-cni
  23 │                               readOnly: true
  24 └                             - mountPath: /var/lib/etcd
  ..   
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────



namespace: secops, cronjob: kube-hunter (kubernetes)
====================================================
Tests: 110 (SUCCESSES: 97, FAILURES: 13)
Failures: 13 (UNKNOWN: 0, LOW: 9, MEDIUM: 3, HIGH: 1, CRITICAL: 0)

AVD-KSV-0001 (MEDIUM): Container 'kube-hunter' of CronJob 'kube-hunter' should set 'securityContext.allowPrivilegeEscalation' to false
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node.

See https://avd.aquasec.com/misconfig/ksv001
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-hunter:16-21
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌                         - args:
  17 │                             - --pod
  18 │                           command:
  19 │                             - kube-hunter
  20 │                           image: aquasec/kube-hunter:0.6.8
  21 └                           name: kube-hunter
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0003 (LOW): Container 'kube-hunter' of CronJob 'kube-hunter' should add 'ALL' to 'securityContext.capabilities.drop'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
The container should drop all default capabilities and add only those that are needed for its execution.

See https://avd.aquasec.com/misconfig/ksv003
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-hunter:16-21
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌                         - args:
  17 │                             - --pod
  18 │                           command:
  19 │                             - kube-hunter
  20 │                           image: aquasec/kube-hunter:0.6.8
  21 └                           name: kube-hunter
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0011 (LOW): Container 'kube-hunter' of CronJob 'kube-hunter' should set 'resources.limits.cpu'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Enforcing CPU limits prevents DoS via resource exhaustion.

See https://avd.aquasec.com/misconfig/ksv011
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-hunter:16-21
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌                         - args:
  17 │                             - --pod
  18 │                           command:
  19 │                             - kube-hunter
  20 │                           image: aquasec/kube-hunter:0.6.8
  21 └                           name: kube-hunter
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0012 (MEDIUM): Container 'kube-hunter' of CronJob 'kube-hunter' should set 'securityContext.runAsNonRoot' to true
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Force the running image to run as a non-root user to ensure least privileges.

See https://avd.aquasec.com/misconfig/ksv012
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-hunter:16-21
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌                         - args:
  17 │                             - --pod
  18 │                           command:
  19 │                             - kube-hunter
  20 │                           image: aquasec/kube-hunter:0.6.8
  21 └                           name: kube-hunter
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0014 (HIGH): Container 'kube-hunter' of CronJob 'kube-hunter' should set 'securityContext.readOnlyRootFilesystem' to true
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk.

See https://avd.aquasec.com/misconfig/ksv014
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-hunter:16-21
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌                         - args:
  17 │                             - --pod
  18 │                           command:
  19 │                             - kube-hunter
  20 │                           image: aquasec/kube-hunter:0.6.8
  21 └                           name: kube-hunter
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0015 (LOW): Container 'kube-hunter' of CronJob 'kube-hunter' should set 'resources.requests.cpu'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
When containers have resource requests specified, the scheduler can make better decisions about which nodes to place pods on, and how to deal with resource contention.

See https://avd.aquasec.com/misconfig/ksv015
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-hunter:16-21
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌                         - args:
  17 │                             - --pod
  18 │                           command:
  19 │                             - kube-hunter
  20 │                           image: aquasec/kube-hunter:0.6.8
  21 └                           name: kube-hunter
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0016 (LOW): Container 'kube-hunter' of CronJob 'kube-hunter' should set 'resources.requests.memory'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
When containers have memory requests specified, the scheduler can make better decisions about which nodes to place pods on, and how to deal with resource contention.

See https://avd.aquasec.com/misconfig/ksv016
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-hunter:16-21
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌                         - args:
  17 │                             - --pod
  18 │                           command:
  19 │                             - kube-hunter
  20 │                           image: aquasec/kube-hunter:0.6.8
  21 └                           name: kube-hunter
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0018 (LOW): Container 'kube-hunter' of CronJob 'kube-hunter' should set 'resources.limits.memory'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Enforcing memory limits prevents DoS via resource exhaustion.

See https://avd.aquasec.com/misconfig/ksv018
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-hunter:16-21
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌                         - args:
  17 │                             - --pod
  18 │                           command:
  19 │                             - kube-hunter
  20 │                           image: aquasec/kube-hunter:0.6.8
  21 └                           name: kube-hunter
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0020 (LOW): Container 'kube-hunter' of CronJob 'kube-hunter' should set 'securityContext.runAsUser' > 10000
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Force the container to run with user ID > 10000 to avoid conflicts with the host’s user table.

See https://avd.aquasec.com/misconfig/ksv020
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-hunter:16-21
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌                         - args:
  17 │                             - --pod
  18 │                           command:
  19 │                             - kube-hunter
  20 │                           image: aquasec/kube-hunter:0.6.8
  21 └                           name: kube-hunter
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0021 (LOW): Container 'kube-hunter' of CronJob 'kube-hunter' should set 'securityContext.runAsGroup' > 10000
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Force the container to run with group ID > 10000 to avoid conflicts with the host’s user table.

See https://avd.aquasec.com/misconfig/ksv021
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-hunter:16-21
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌                         - args:
  17 │                             - --pod
  18 │                           command:
  19 │                             - kube-hunter
  20 │                           image: aquasec/kube-hunter:0.6.8
  21 └                           name: kube-hunter
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0030 (LOW): Either Pod or Container should set 'securityContext.seccompProfile.type' to 'RuntimeDefault'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
According to pod security standard 'Seccomp', the RuntimeDefault seccomp profile must be required, or allow specific additional profiles.

See https://avd.aquasec.com/misconfig/ksv030
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-hunter:16-21
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌                         - args:
  17 │                             - --pod
  18 │                           command:
  19 │                             - kube-hunter
  20 │                           image: aquasec/kube-hunter:0.6.8
  21 └                           name: kube-hunter
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0104 (MEDIUM): container "kube-hunter" of cronjob "kube-hunter" in "secops" namespace should specify a seccomp profile
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
A program inside the container can bypass Seccomp protection policies.

See https://avd.aquasec.com/misconfig/ksv104
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0106 (LOW): container should drop all
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Containers must drop ALL capabilities, and are only permitted to add back the NET_BIND_SERVICE capability.

See https://avd.aquasec.com/misconfig/ksv106
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, cronjob: kube-hunter:16-21
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌                         - args:
  17 │                             - --pod
  18 │                           command:
  19 │                             - kube-hunter
  20 │                           image: aquasec/kube-hunter:0.6.8
  21 └                           name: kube-hunter
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────



namespace: secops, deployment: juice-shop (kubernetes)
======================================================
Tests: 110 (SUCCESSES: 96, FAILURES: 14)
Failures: 14 (UNKNOWN: 0, LOW: 9, MEDIUM: 4, HIGH: 1, CRITICAL: 0)

AVD-KSV-0001 (MEDIUM): Container 'juice-shop' of Deployment 'juice-shop' should set 'securityContext.allowPrivilegeEscalation' to false
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node.

See https://avd.aquasec.com/misconfig/ksv001
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: juice-shop:17-18
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  17 ┌                 - image: bkimminich/juice-shop
  18 └                   name: juice-shop
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0003 (LOW): Container 'juice-shop' of Deployment 'juice-shop' should add 'ALL' to 'securityContext.capabilities.drop'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
The container should drop all default capabilities and add only those that are needed for its execution.

See https://avd.aquasec.com/misconfig/ksv003
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: juice-shop:17-18
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  17 ┌                 - image: bkimminich/juice-shop
  18 └                   name: juice-shop
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0011 (LOW): Container 'juice-shop' of Deployment 'juice-shop' should set 'resources.limits.cpu'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Enforcing CPU limits prevents DoS via resource exhaustion.

See https://avd.aquasec.com/misconfig/ksv011
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: juice-shop:17-18
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  17 ┌                 - image: bkimminich/juice-shop
  18 └                   name: juice-shop
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0012 (MEDIUM): Container 'juice-shop' of Deployment 'juice-shop' should set 'securityContext.runAsNonRoot' to true
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Force the running image to run as a non-root user to ensure least privileges.

See https://avd.aquasec.com/misconfig/ksv012
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: juice-shop:17-18
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  17 ┌                 - image: bkimminich/juice-shop
  18 └                   name: juice-shop
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0013 (MEDIUM): Container 'juice-shop' of Deployment 'juice-shop' should specify an image tag
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
It is best to avoid using the ':latest' image tag when deploying containers in production. Doing so makes it hard to track which version of the image is running, and hard to roll back the version.

See https://avd.aquasec.com/misconfig/ksv013
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: juice-shop:17-18
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  17 ┌                 - image: bkimminich/juice-shop
  18 └                   name: juice-shop
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0014 (HIGH): Container 'juice-shop' of Deployment 'juice-shop' should set 'securityContext.readOnlyRootFilesystem' to true
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk.

See https://avd.aquasec.com/misconfig/ksv014
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: juice-shop:17-18
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  17 ┌                 - image: bkimminich/juice-shop
  18 └                   name: juice-shop
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0015 (LOW): Container 'juice-shop' of Deployment 'juice-shop' should set 'resources.requests.cpu'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
When containers have resource requests specified, the scheduler can make better decisions about which nodes to place pods on, and how to deal with resource contention.

See https://avd.aquasec.com/misconfig/ksv015
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: juice-shop:17-18
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  17 ┌                 - image: bkimminich/juice-shop
  18 └                   name: juice-shop
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0016 (LOW): Container 'juice-shop' of Deployment 'juice-shop' should set 'resources.requests.memory'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
When containers have memory requests specified, the scheduler can make better decisions about which nodes to place pods on, and how to deal with resource contention.

See https://avd.aquasec.com/misconfig/ksv016
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: juice-shop:17-18
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  17 ┌                 - image: bkimminich/juice-shop
  18 └                   name: juice-shop
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0018 (LOW): Container 'juice-shop' of Deployment 'juice-shop' should set 'resources.limits.memory'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Enforcing memory limits prevents DoS via resource exhaustion.

See https://avd.aquasec.com/misconfig/ksv018
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: juice-shop:17-18
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  17 ┌                 - image: bkimminich/juice-shop
  18 └                   name: juice-shop
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0020 (LOW): Container 'juice-shop' of Deployment 'juice-shop' should set 'securityContext.runAsUser' > 10000
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Force the container to run with user ID > 10000 to avoid conflicts with the host’s user table.

See https://avd.aquasec.com/misconfig/ksv020
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: juice-shop:17-18
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  17 ┌                 - image: bkimminich/juice-shop
  18 └                   name: juice-shop
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0021 (LOW): Container 'juice-shop' of Deployment 'juice-shop' should set 'securityContext.runAsGroup' > 10000
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Force the container to run with group ID > 10000 to avoid conflicts with the host’s user table.

See https://avd.aquasec.com/misconfig/ksv021
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: juice-shop:17-18
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  17 ┌                 - image: bkimminich/juice-shop
  18 └                   name: juice-shop
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0030 (LOW): Either Pod or Container should set 'securityContext.seccompProfile.type' to 'RuntimeDefault'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
According to pod security standard 'Seccomp', the RuntimeDefault seccomp profile must be required, or allow specific additional profiles.

See https://avd.aquasec.com/misconfig/ksv030
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: juice-shop:17-18
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  17 ┌                 - image: bkimminich/juice-shop
  18 └                   name: juice-shop
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0104 (MEDIUM): container "juice-shop" of deployment "juice-shop" in "secops" namespace should specify a seccomp profile
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
A program inside the container can bypass Seccomp protection policies.

See https://avd.aquasec.com/misconfig/ksv104
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0106 (LOW): container should drop all
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Containers must drop ALL capabilities, and are only permitted to add back the NET_BIND_SERVICE capability.

See https://avd.aquasec.com/misconfig/ksv106
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: juice-shop:17-18
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  17 ┌                 - image: bkimminich/juice-shop
  18 └                   name: juice-shop
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────



namespace: secops, deployment: log-collector (kubernetes)
=========================================================
Tests: 110 (SUCCESSES: 96, FAILURES: 14)
Failures: 14 (UNKNOWN: 0, LOW: 9, MEDIUM: 4, HIGH: 1, CRITICAL: 0)

AVD-KSV-0001 (MEDIUM): Container 'log-collector' of Deployment 'log-collector' should set 'securityContext.allowPrivilegeEscalation' to false
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node.

See https://avd.aquasec.com/misconfig/ksv001
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: log-collector:18-22
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  18 ┌                 - image: rorexz/tfm@sha256:9c0bae70d6aa148ec751ede62025497f510bd4a40186c3754613bf3de47b02eb
  19 │                   imagePullPolicy: Always
  20 │                   name: log-collector
  21 │                   ports:
  22 └                     - containerPort: 80
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0003 (LOW): Container 'log-collector' of Deployment 'log-collector' should add 'ALL' to 'securityContext.capabilities.drop'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
The container should drop all default capabilities and add only those that are needed for its execution.

See https://avd.aquasec.com/misconfig/ksv003
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: log-collector:18-22
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  18 ┌                 - image: rorexz/tfm@sha256:9c0bae70d6aa148ec751ede62025497f510bd4a40186c3754613bf3de47b02eb
  19 │                   imagePullPolicy: Always
  20 │                   name: log-collector
  21 │                   ports:
  22 └                     - containerPort: 80
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0011 (LOW): Container 'log-collector' of Deployment 'log-collector' should set 'resources.limits.cpu'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Enforcing CPU limits prevents DoS via resource exhaustion.

See https://avd.aquasec.com/misconfig/ksv011
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: log-collector:18-22
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  18 ┌                 - image: rorexz/tfm@sha256:9c0bae70d6aa148ec751ede62025497f510bd4a40186c3754613bf3de47b02eb
  19 │                   imagePullPolicy: Always
  20 │                   name: log-collector
  21 │                   ports:
  22 └                     - containerPort: 80
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0012 (MEDIUM): Container 'log-collector' of Deployment 'log-collector' should set 'securityContext.runAsNonRoot' to true
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Force the running image to run as a non-root user to ensure least privileges.

See https://avd.aquasec.com/misconfig/ksv012
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: log-collector:18-22
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  18 ┌                 - image: rorexz/tfm@sha256:9c0bae70d6aa148ec751ede62025497f510bd4a40186c3754613bf3de47b02eb
  19 │                   imagePullPolicy: Always
  20 │                   name: log-collector
  21 │                   ports:
  22 └                     - containerPort: 80
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0014 (HIGH): Container 'log-collector' of Deployment 'log-collector' should set 'securityContext.readOnlyRootFilesystem' to true
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk.

See https://avd.aquasec.com/misconfig/ksv014
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: log-collector:18-22
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  18 ┌                 - image: rorexz/tfm@sha256:9c0bae70d6aa148ec751ede62025497f510bd4a40186c3754613bf3de47b02eb
  19 │                   imagePullPolicy: Always
  20 │                   name: log-collector
  21 │                   ports:
  22 └                     - containerPort: 80
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0015 (LOW): Container 'log-collector' of Deployment 'log-collector' should set 'resources.requests.cpu'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
When containers have resource requests specified, the scheduler can make better decisions about which nodes to place pods on, and how to deal with resource contention.

See https://avd.aquasec.com/misconfig/ksv015
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: log-collector:18-22
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  18 ┌                 - image: rorexz/tfm@sha256:9c0bae70d6aa148ec751ede62025497f510bd4a40186c3754613bf3de47b02eb
  19 │                   imagePullPolicy: Always
  20 │                   name: log-collector
  21 │                   ports:
  22 └                     - containerPort: 80
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0016 (LOW): Container 'log-collector' of Deployment 'log-collector' should set 'resources.requests.memory'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
When containers have memory requests specified, the scheduler can make better decisions about which nodes to place pods on, and how to deal with resource contention.

See https://avd.aquasec.com/misconfig/ksv016
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: log-collector:18-22
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  18 ┌                 - image: rorexz/tfm@sha256:9c0bae70d6aa148ec751ede62025497f510bd4a40186c3754613bf3de47b02eb
  19 │                   imagePullPolicy: Always
  20 │                   name: log-collector
  21 │                   ports:
  22 └                     - containerPort: 80
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0018 (LOW): Container 'log-collector' of Deployment 'log-collector' should set 'resources.limits.memory'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Enforcing memory limits prevents DoS via resource exhaustion.

See https://avd.aquasec.com/misconfig/ksv018
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: log-collector:18-22
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  18 ┌                 - image: rorexz/tfm@sha256:9c0bae70d6aa148ec751ede62025497f510bd4a40186c3754613bf3de47b02eb
  19 │                   imagePullPolicy: Always
  20 │                   name: log-collector
  21 │                   ports:
  22 └                     - containerPort: 80
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0020 (LOW): Container 'log-collector' of Deployment 'log-collector' should set 'securityContext.runAsUser' > 10000
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Force the container to run with user ID > 10000 to avoid conflicts with the host’s user table.

See https://avd.aquasec.com/misconfig/ksv020
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: log-collector:18-22
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  18 ┌                 - image: rorexz/tfm@sha256:9c0bae70d6aa148ec751ede62025497f510bd4a40186c3754613bf3de47b02eb
  19 │                   imagePullPolicy: Always
  20 │                   name: log-collector
  21 │                   ports:
  22 └                     - containerPort: 80
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0021 (LOW): Container 'log-collector' of Deployment 'log-collector' should set 'securityContext.runAsGroup' > 10000
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Force the container to run with group ID > 10000 to avoid conflicts with the host’s user table.

See https://avd.aquasec.com/misconfig/ksv021
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: log-collector:18-22
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  18 ┌                 - image: rorexz/tfm@sha256:9c0bae70d6aa148ec751ede62025497f510bd4a40186c3754613bf3de47b02eb
  19 │                   imagePullPolicy: Always
  20 │                   name: log-collector
  21 │                   ports:
  22 └                     - containerPort: 80
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0030 (LOW): Either Pod or Container should set 'securityContext.seccompProfile.type' to 'RuntimeDefault'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
According to pod security standard 'Seccomp', the RuntimeDefault seccomp profile must be required, or allow specific additional profiles.

See https://avd.aquasec.com/misconfig/ksv030
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: log-collector:18-22
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  18 ┌                 - image: rorexz/tfm@sha256:9c0bae70d6aa148ec751ede62025497f510bd4a40186c3754613bf3de47b02eb
  19 │                   imagePullPolicy: Always
  20 │                   name: log-collector
  21 │                   ports:
  22 └                     - containerPort: 80
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0104 (MEDIUM): container "log-collector" of deployment "log-collector" in "secops" namespace should specify a seccomp profile
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
A program inside the container can bypass Seccomp protection policies.

See https://avd.aquasec.com/misconfig/ksv104
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0106 (LOW): container should drop all
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Containers must drop ALL capabilities, and are only permitted to add back the NET_BIND_SERVICE capability.

See https://avd.aquasec.com/misconfig/ksv106
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 namespace: secops, deployment: log-collector:18-22
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  18 ┌                 - image: rorexz/tfm@sha256:9c0bae70d6aa148ec751ede62025497f510bd4a40186c3754613bf3de47b02eb
  19 │                   imagePullPolicy: Always
  20 │                   name: log-collector
  21 │                   ports:
  22 └                     - containerPort: 80
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-KSV-0117 (MEDIUM): deployment log-collector in secops namespace should not set spec.template.spec.containers.ports.containerPort to less than 1024
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
The ports which are lower than 1024 receive and transmit various sensitive and privileged data. Allowing containers to use them can bring serious implications.

See https://avd.aquasec.com/misconfig/ksv117
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


