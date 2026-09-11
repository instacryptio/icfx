# CHANGELOG


**v0.1.6 - 09-11-2026**

- Pin goroutine to OS thread for macos
- SetOpenExclusive(false) for darwin
- hidList and pcscList fixes


**v0.1.5 - 09-10-2026**

- Migrated to hidapi (removed ykpers)
- Migrated to hidapi (removed ykpers)
- Added nitrokey 1st pass proper (needs testing)


**v0.1.4 - 09-09-2026**

- Fixed Windows identity store


**v0.1.3 - 09-07-2026**

- Bumped go-libfido2
- Added build tags for hardware keys opt-out


**v0.1.2 - 09-07-2026**

- Passphrases and ChalResp hardening
- Improved import identity
- Fixed id removal & hw key delete gate


**v0.1.1 - 09-05-2026**

- Cross-platform keychain fix


**v0.1.0 - 09-01-2026**

- Initial release
