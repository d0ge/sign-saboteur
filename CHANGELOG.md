# Changelog

## [1.0.4] - 2024-05-02

### Changed

- Code refactoring

## [1.0.3] - 2024-04-25

### Added

- New key derivation: Ruby Key Generator
- JSON editor for Ruby tokens

### Changed

- Ruby on rails signer was updated to support different Key Generators

## [1.0.2] - 2024-04-04

### Changed

- Code refactoring

## [1.0.1] - 2024-04-03

### Changed

- Default Secret Keys now available at Wordlist View
- The com.nimbusds.jwt SignedJWT parser added to the finder logic. _Note_ RSA and ECDSA not supported by the extension yet


## [1.0.0] - 2024-03-27

### Changed

- Tool name changed to SignSaboteur
- Unknown web signed tokens with empty body excluded from search algorithm to avoid duplicates
- JWT finder separated from Flask/Django implementation

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