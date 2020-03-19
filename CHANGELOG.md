# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2020-03-19
### Changed
- Added GPL header to template file.

## [0.2.0] - 2020-01-03
### Added
- Handle data packet trailers if present.
- Show controllee/controller IDs in command packets.
### Changed
- Display Discrete I/O fields in hexadecimal.
- More detailed text for enumerated types in context header and CAM field.

## [0.1.0] - 2019-12-30
### Added
- Initial Wireshark plugin for VITA 49.2 packets.
- View data, context and command packets.
- Partial CIF0 and CIF1 support.
