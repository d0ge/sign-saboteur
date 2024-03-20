# Changelog

## [0.0.8] - 2024-03-20

### Added

- Burp Suite Pro active scan supported now. All identified signed string are scanned for known secrets with Fast algorithm

### Changed

- Regex token search method was removed due to poor performance. New search algorithm was introduced instead.

## [0.0.7] - 2024-03-12

### Added

- JWT Tab was added for testing purposes
- Default keys dictionary

### Changed

- Response body was removed from token parser logic due to performance issues

## [0.0.6] - 2024-02-06

### Added

- Ruby signed cookie Tab
- Multithreading feature is available for brute force attack

### Changed

- Brute force Deep mode supports Ruby, Ruby5 and Ruby truncated hashing key derivation

## [0.0.5] - 2024-01-07

### Added

- Manual secret and salt item creation

### Changed

- Brute force uses all known keys for all attacks mode by default

## [0.0.4] - 2024-01-07

### Changed

- Github actions

## [0.0.2] - 2024-01-05

### Added

- Unknown signed string tab.
- Enabled signers setting added to the main tab
- _Known keys_ brute force technic added to the Attack mode

### Changed

- Upgrade dependencies: org.json:json 