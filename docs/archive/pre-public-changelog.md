# Archived Pre-Public Changelog

> This file preserves an automatically generated development changelog imported
> before the current public repository history. Many commit, issue, comparison,
> and tag links do not resolve in this repository. It is historical context, not
> evidence of published GitHub releases.

## Unreleased

### Changed

- Re-license the Ravage core workspace and publishable packages under
  `AGPL-3.0-only`.
- Keep Markdown and JSON pentest reports in core while reserving professional
  PDF and DOCX exports for the separately licensed Ravage Pro extension.

## [0.5.0](https://github.com/duriantaco/ravage/compare/v0.4.0...v0.5.0) (2026-07-11)


### Features

* add competitor benchmark harness ([8c8ea74](https://github.com/duriantaco/ravage/commit/8c8ea74d689c84435d9e3cbc26e9f77dfd1002c0))
* add competitor benchmark harness ([573c512](https://github.com/duriantaco/ravage/commit/573c51210a8bde054623bc161cb89cf1f25bb194))

## [0.4.0](https://github.com/duriantaco/ravage/compare/v0.3.0...v0.4.0) (2026-06-19)


### Features

* **agent:** add deterministic black-box probing ([#76](https://github.com/duriantaco/ravage/issues/76)) ([89a0801](https://github.com/duriantaco/ravage/commit/89a0801d7c4b8fdb070455040cf715158c8a8261))
* **agent:** add free-roam closure runtime ([#79](https://github.com/duriantaco/ravage/issues/79)) ([91ae12e](https://github.com/duriantaco/ravage/commit/91ae12e3152086ec3329a7ebaf2b07c3085a89f7))
* **agent:** add free-roam workflow taxonomy ([#81](https://github.com/duriantaco/ravage/issues/81)) ([796e6c6](https://github.com/duriantaco/ravage/commit/796e6c61d4e0a4f5213064300d2d1f1748646da5))
* **agent:** add native anthropic adapter ([#72](https://github.com/duriantaco/ravage/issues/72)) ([64f0c86](https://github.com/duriantaco/ravage/commit/64f0c86b5b0c82e0f2112ebba53a27fa7801bb57))
* **agent:** add proof bundle evidence infrastructure ([#78](https://github.com/duriantaco/ravage/issues/78)) ([465d715](https://github.com/duriantaco/ravage/commit/465d7155e00dd46f92f23af218a827634ebaea7b))
* **agent:** add registered password update IDOR chain ([#65](https://github.com/duriantaco/ravage/issues/65)) ([1da36d6](https://github.com/duriantaco/ravage/commit/1da36d63a5e9b68895dfafe962887146484b27e8))
* **agent:** detect Apache path traversal signals ([#60](https://github.com/duriantaco/ravage/issues/60)) ([78811be](https://github.com/duriantaco/ravage/commit/78811be68c8a8ebb5a684c1445ec8c47ad7dae7e))
* **agent:** detect pickle cookie deserialization candidates ([#57](https://github.com/duriantaco/ravage/issues/57)) ([d6f211e](https://github.com/duriantaco/ravage/commit/d6f211e44b09050ea4cdbc8e14d48c6266189cd0))
* **agent:** expand free-roam taxonomy runtime ([#86](https://github.com/duriantaco/ravage/issues/86)) ([7f245e7](https://github.com/duriantaco/ravage/commit/7f245e76e6cc32cf989094ee7580f18b6740360b))
* **agent:** gate final on objective evidence ([#70](https://github.com/duriantaco/ravage/issues/70)) ([4facaea](https://github.com/duriantaco/ravage/commit/4facaeae8e9de64a31de25b22c680628a23b5456))
* **agent:** generalize source-guided GraphQL IDOR queries ([#82](https://github.com/duriantaco/ravage/issues/82)) ([133f101](https://github.com/duriantaco/ravage/commit/133f1010e8732de1cfa04d9a81c561c052e56b55))
* **agent:** reduce repeated ai-web turns ([#69](https://github.com/duriantaco/ravage/issues/69)) ([b88bce4](https://github.com/duriantaco/ravage/commit/b88bce48253b27e5dc23ffc7efaf57642a412f4a))
* **agent:** run Apache path traversal workflow ([#61](https://github.com/duriantaco/ravage/issues/61)) ([e3fabb9](https://github.com/duriantaco/ravage/commit/e3fabb9544917e5a937b353c2e5ae816b4f3d77a))
* **agent:** run pickle cookie deserialization workflow ([#59](https://github.com/duriantaco/ravage/issues/59)) ([01e49ab](https://github.com/duriantaco/ravage/commit/01e49ab2e718fb93d02f2149d36d53a0a3231cda))
* **benchmark:** add normalized run trace telemetry ([#66](https://github.com/duriantaco/ravage/issues/66)) ([25ae8c3](https://github.com/duriantaco/ravage/commit/25ae8c30021b8220e265315a769a46293f7758c5))
* **benchmark:** add ravage self adapter ([#67](https://github.com/duriantaco/ravage/issues/67)) ([7cef44d](https://github.com/duriantaco/ravage/commit/7cef44d348ae8692e896d8c17f747b007b505354))
* **benchmark:** add trace quality graders ([#68](https://github.com/duriantaco/ravage/issues/68)) ([832b36e](https://github.com/duriantaco/ravage/commit/832b36e79b07d15e9dc50e7b66bf84f6c4839297))
* **cli:** add setup and init helpers ([#90](https://github.com/duriantaco/ravage/issues/90)) ([ac5ae06](https://github.com/duriantaco/ravage/commit/ac5ae06228728410220a44a19f36771489d01503))
* **dashboard:** refresh live run view ([#84](https://github.com/duriantaco/ravage/issues/84)) ([95bd248](https://github.com/duriantaco/ravage/commit/95bd248e2d1767a913d0538d63ad750f871216ca))
* **probes:** expand LFI and command payload coverage ([#99](https://github.com/duriantaco/ravage/issues/99)) ([a7e80ac](https://github.com/duriantaco/ravage/commit/a7e80aca07f40c47c5c8307267af02c436715887))
* **scan:** summarize progress in terminal output ([#93](https://github.com/duriantaco/ravage/issues/93)) ([55d7bf2](https://github.com/duriantaco/ravage/commit/55d7bf22e70602a1e5869945536f63bc3bb2b7ce))
* **xben:** add taxonomy and benchmark guardrails ([#77](https://github.com/duriantaco/ravage/issues/77)) ([3f6e656](https://github.com/duriantaco/ravage/commit/3f6e656687ad5a733ae349cda0751277fdf7368e))


### Bug Fixes

* **agent:** bound clean sqli probe requests ([#74](https://github.com/duriantaco/ravage/issues/74)) ([6d021d5](https://github.com/duriantaco/ravage/commit/6d021d5a1043e6f3d3eedf947d2b102d2d47247f))
* **agent:** follow post-auth perimeter probes ([#75](https://github.com/duriantaco/ravage/issues/75)) ([b8af88a](https://github.com/duriantaco/ravage/commit/b8af88aa12a8ae4ba10fd6e8848d84f14b51dbaf))
* **agent:** keep confirmed sqli probes within budget ([#73](https://github.com/duriantaco/ravage/issues/73)) ([2386254](https://github.com/duriantaco/ravage/commit/2386254a58b1b9420b68db2c28598fd11ba07ce1))
* **agent:** keep free-roam controllers objective-sticky ([#80](https://github.com/duriantaco/ravage/issues/80)) ([32271ab](https://github.com/duriantaco/ravage/commit/32271ab93a31100e038fc1a0371032003769a2cb))
* **agent:** parse SQL seed auth credentials safely ([#62](https://github.com/duriantaco/ravage/issues/62)) ([a67ecbe](https://github.com/duriantaco/ravage/commit/a67ecbe8d076938317edc8df88062abd91fa2ae6))
* **agent:** rank header trust routes by evidence ([#63](https://github.com/duriantaco/ravage/issues/63)) ([0a71c9f](https://github.com/duriantaco/ravage/commit/0a71c9f46c299970af8f4e77fafd860fdcb43c34))
* **agent:** tighten source login success detection ([#64](https://github.com/duriantaco/ravage/issues/64)) ([fd754e9](https://github.com/duriantaco/ravage/commit/fd754e948df92e608f2f7c350a30025b680711be))
* **cli:** keep stale orchestrator entrypoint helpful ([#91](https://github.com/duriantaco/ravage/issues/91)) ([2f9b237](https://github.com/duriantaco/ravage/commit/2f9b23746a76a916c51aa9e6e4376aa308ed2264))
* **scope:** preserve local redirect ports ([#95](https://github.com/duriantaco/ravage/issues/95)) ([9a988cb](https://github.com/duriantaco/ravage/commit/9a988cbf06eacf9bc55bb39e0e5e4cc80ede6b1c))
* **tool-runtime:** improve requests shim compatibility ([#96](https://github.com/duriantaco/ravage/issues/96)) ([aac12dd](https://github.com/duriantaco/ravage/commit/aac12dda8170fff8a3a87f521c23d3396ca3ccfa))
* **xben:** declare flag build args before use ([#85](https://github.com/duriantaco/ravage/issues/85)) ([920352a](https://github.com/duriantaco/ravage/commit/920352a019cca9b9873a0684e1d1ba0e7f92bd1d))
* **xben:** preserve urlopen test hook ([#94](https://github.com/duriantaco/ravage/issues/94)) ([3220808](https://github.com/duriantaco/ravage/commit/3220808d667ac2f1fa3ec73ab4f43fde6ebe378c))

## [0.3.0](https://github.com/duriantaco/ravage/compare/v0.2.0...v0.3.0) (2026-06-05)


### Features

* **agent:** close generic random benchmark gaps ([#42](https://github.com/duriantaco/ravage/issues/42)) ([22d8b17](https://github.com/duriantaco/ravage/commit/22d8b170da9059ccd15a370927574d6075eba75e))
* **agent:** expand source-guided probes and reporting ([#31](https://github.com/duriantaco/ravage/issues/31)) ([48a98cc](https://github.com/duriantaco/ravage/commit/48a98ccc5e4f62422f7b8247ef5bfb586efa63e6))
* **agent:** prioritize source-guided workflows ([#33](https://github.com/duriantaco/ravage/issues/33)) ([0576313](https://github.com/duriantaco/ravage/commit/05763133efe31bf0d3bab3c4e35d5bd10b0726dc))


### Bug Fixes

* **agent:** close generic source-guided gaps ([#40](https://github.com/duriantaco/ravage/issues/40)) ([752c9b1](https://github.com/duriantaco/ravage/commit/752c9b197219eea94e863437b90fe24ebc8f672a))
* **agent:** extend source-guided ssti file reads ([#56](https://github.com/duriantaco/ravage/issues/56)) ([cfadd8f](https://github.com/duriantaco/ravage/commit/cfadd8fddb3a2cd30d98dac3c5b677aee72d99e9))
* **agent:** guard source-guided workflow drift ([#36](https://github.com/duriantaco/ravage/issues/36)) ([56618b9](https://github.com/duriantaco/ravage/commit/56618b9b5f0ee3bb94b733451de7355cd174880a))
* **agent:** harden generic source-guided workflows ([#37](https://github.com/duriantaco/ravage/issues/37)) ([55f48c7](https://github.com/duriantaco/ravage/commit/55f48c7d02ea87bb878f50431ed297866062c1a7))
* **agent:** harden source-guided pentest workflows ([#34](https://github.com/duriantaco/ravage/issues/34)) ([d7eface](https://github.com/duriantaco/ravage/commit/d7efaceb43093dcca5308b9a985e1497a348beff))
* **agent:** improve source-guided upload flow ([#55](https://github.com/duriantaco/ravage/issues/55)) ([4aebdf7](https://github.com/duriantaco/ravage/commit/4aebdf79728c6c9e7c9a3e528a46f4dea3a52a4f))
* **agent:** prioritize source-guided workflows ([#54](https://github.com/duriantaco/ravage/issues/54)) ([6d0d6a3](https://github.com/duriantaco/ravage/commit/6d0d6a3f021e6e274a885bc2243e7fcea2f938fc))
* **xben:** add setup guards for random samples ([#53](https://github.com/duriantaco/ravage/issues/53)) ([b9576b7](https://github.com/duriantaco/ravage/commit/b9576b77d660e41a2cb8f85d37598cc31242b86f))

## [0.2.0](https://github.com/duriantaco/ravage/compare/v0.1.0...v0.2.0) (2026-05-31)


### Features

* **agent:** isolate untrusted tool observations ([#25](https://github.com/duriantaco/ravage/issues/25)) ([997da40](https://github.com/duriantaco/ravage/commit/997da40194f693b2808271feaec6f9b2d4f2b155))
* **audit:** add hash-chained verification ([#19](https://github.com/duriantaco/ravage/issues/19)) ([caa924d](https://github.com/duriantaco/ravage/commit/caa924d832242fcf915b85ac626dede016930b76))
* **dashboard:** clarify live run progress ([#28](https://github.com/duriantaco/ravage/issues/28)) ([4c00c11](https://github.com/duriantaco/ravage/commit/4c00c11858cdb63689ae668822b0ed4795b5914c))
* **eval:** add isolated competitor harness ([#26](https://github.com/duriantaco/ravage/issues/26)) ([cac8fef](https://github.com/duriantaco/ravage/commit/cac8fef75dc82047fd1b58407c98d493313ce7c1))
* **memory:** redact high-entropy tokens ([#24](https://github.com/duriantaco/ravage/issues/24)) ([2749e76](https://github.com/duriantaco/ravage/commit/2749e76f328455d52d11bec3f46b47347a1d3d75))
* **scope:** enforce Docker tool firewall rules ([#23](https://github.com/duriantaco/ravage/issues/23)) ([4066a60](https://github.com/duriantaco/ravage/commit/4066a60b8fae32171c8321f4c7c29e3edb155d5b))
* **tools:** smooth source-checkout installation ([#27](https://github.com/duriantaco/ravage/issues/27)) ([f6f3a59](https://github.com/duriantaco/ravage/commit/f6f3a59f21f7fe76293e6dcd0e4394f712763f2c))


### Bug Fixes

* **agent:** gate confirmed finding evidence ([#30](https://github.com/duriantaco/ravage/issues/30)) ([041704c](https://github.com/duriantaco/ravage/commit/041704c5738ba5b0e939b5b084cce0b6851b92d6))
* **audit:** avoid variable SQL migration statement ([#21](https://github.com/duriantaco/ravage/issues/21)) ([a205b48](https://github.com/duriantaco/ravage/commit/a205b4818ae7871af2f0260047ff166c40c104a8))
* **dashboard:** show friendly tool labels ([#29](https://github.com/duriantaco/ravage/issues/29)) ([b95691e](https://github.com/duriantaco/ravage/commit/b95691ef478fd9480ee8f3eccd2cf661717c89f6))
* **scope:** harden host validation and DNS pinning ([#22](https://github.com/duriantaco/ravage/issues/22)) ([dada322](https://github.com/duriantaco/ravage/commit/dada32258f1ecf03086cbaf365c939744cff3ef4))

## [0.1.0](https://github.com/duriantaco/ravage/compare/v0.0.1...v0.1.0) (2026-05-29)


### Features

* **ai-agent:** generalize evidence-gated findings ([#15](https://github.com/duriantaco/ravage/issues/15)) ([9e27383](https://github.com/duriantaco/ravage/commit/9e2738336cd6754ca735f36aae67b27c51004c49))
* **ai-agent:** generalize evidence-gated findings ([#16](https://github.com/duriantaco/ravage/issues/16)) ([5a36fcf](https://github.com/duriantaco/ravage/commit/5a36fcf03bd6aa1e4fb5c47fb2893243ecf7c829))

## 0.0.1 - Unreleased

- Initial Ravage runtime package.
- Initial `ravage-schemas` companion package.
- Scoped `ravage attack`, deterministic `ravage scan`, local labs, audit logs,
  report generation, benchmark harnesses, and optional local memory.
- PyPI Trusted Publishing workflow for the first release.
