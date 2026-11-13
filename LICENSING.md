# Licensing

DeskID is source-available. Anyone can read the code, build it and check what it does. Selling it, redistributing it or building a product on it needs a written license from the licensor.

The licensor is Maksym Bardakh, the copyright holder of this repository.

The binding terms are [LICENSE.md](LICENSE.md), which is the PolyForm Strict License 1.0.0 without changes, and the section "Additional permissions" on this page. Everything else on this page is a plain-language summary. Where the summary and the binding terms differ, the binding terms apply.

## What the terms cover

| Material | Terms |
|---|---|
| Firmware, tests, host tools, scripts and documentation in this repository | PolyForm Strict 1.0.0 with the additional permissions below |
| Components fetched at build time, such as ESP-IDF and TinyUSB | Their own licenses, listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) |
| The DeskID name and logo | No license. See "Names and logos" |

Commits made before this file existed were published with no license. These terms now cover them as well.

## What you may do without asking

- Read the source.
- Build the firmware and tools without changes and run them for a noncommercial purpose: study, research, testing, a hobby build on your own board.
- Use them inside a school, a public research body, a charity or a government institution.
- Fork the repository on GitHub. GitHub's Terms of Service allow that for every public repository. A fork gives you no rights beyond the ones on this page.

## What needs a written license

- Distributing the source or a firmware image, whole or in part, changed or unchanged.
- Shipping the firmware on hardware you make or sell.
- Any commercial use, including a paid service, a product or internal production use at a company, unless an additional permission below covers it.
- Publishing a changed version or a work built on this code.

## Additional permissions

The licensor grants the three permissions below on top of LICENSE.md. They take nothing away from it. The LICENSE.md sections "Patent Defense", "Violations", "No Liability" and "Definitions" apply to them as well.

### 1. Device owners

If you own a DeskID device made by the licensor or under the licensor's written authorisation, you may use the firmware that came on it, and every update the licensor publishes for it, on that device for any purpose, commercial use included. You may also build this repository without changes and install the result on that device.

### 2. Evaluation and audit

Any person or organisation may build and run the firmware and tools without changes in order to evaluate DeskID before a purchase or to audit its security. A commercial purpose is allowed here. This permission ends where production use begins: it does not cover day-to-day use on hardware the licensor did not make or authorise.

### 3. Private changes and security research

You may change the firmware and tools for your own use on hardware you own or are authorised to test, either for a purpose LICENSE.md already permits or for good-faith security research. You may publish what you find, together with the short excerpts and patches needed to explain it. You may not distribute changed source or a changed firmware image.

The licensor will not bring a claim under these terms against research that stays within this permission and follows [SECURITY.md](SECURITY.md).

## Commercial licenses

Manufacturing, OEM integration, redistribution, a maintained private fork and any other use outside these terms are available under a separate written agreement. Open an issue titled "Licensing request" and leave out confidential details. The licensor will answer with a private channel.

## Contributions

Outside pull requests are closed for now. LICENSE.md gives nobody but the licensor the right to distribute changes, and a single owner keeps commercial licensing possible. Bug reports and review comments are welcome as issues. Security reports go through [SECURITY.md](SECURITY.md).

## Names and logos

These terms give no right to the DeskID name or logo. You may use the name to refer to this project truthfully. You may not use it, or a name close enough to confuse a buyer, for your own product, fork, domain or store listing.

## Cryptography and export

The firmware implements ECDSA on P-256 and an HMAC-based random bit generator. Laws on the export, import and use of cryptography differ by country. Meeting the ones that apply to you is your responsibility.

## If the terms are broken

LICENSE.md gives 32 days from written notice to come back into full compliance and to correct past violations. After that every license under these terms ends. The licensor treats the sale of hardware that runs this firmware without a written license as copyright infringement.

## Later versions

A later commit may carry different terms. The terms attached to a commit stay in force for that commit.
