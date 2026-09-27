# Offline operator names

The Web UI maps an exact five- or six-digit MCC/MNC string to a known operator name.
The table is local. The UI does not fetch operator data at run time.

## Source and attribution

The table source is [pbakondy/mcc-mnc-list](https://github.com/pbakondy/mcc-mnc-list).
This change pins the source repository to commit `97bc165252bb9bb5b37946898ec556c29a38feb8`.
The vendored JSON file has SHA-256 `42b5a970ce0fe1046428bc6aeadc3ae0459abccaec6efb907dc7a00ecaa5fa45`.
The commit and hash are stored in `web/data/mcc-mnc-list.metadata.json`.
The accompanying license notice is in `web/data/NOTICE.md`.

The source repository states that its records come from the [Wikipedia Mobile country code page](https://en.wikipedia.org/wiki/Mobile_country_code).
The source repository code uses the MIT license.
The Wikipedia data uses the [Creative Commons Attribution-ShareAlike 4.0 license](https://creativecommons.org/licenses/by-sa/4.0/).
This document keeps both attributions with the vendored data.

The source file contains 3,094 rows.
The generator emits 3,036 named codes with an exact three-digit MCC and two- or three-digit MNC.
It skips nine rows with a non-standard MNC and two rows without a name.
For duplicate codes, it keeps unique source brands, or source operator names when no brand exists.

## Update procedure

1. Replace `web/data/mcc-mnc-list.json` with a reviewed source snapshot.
2. Update `web/data/mcc-mnc-list.metadata.json` with the source commit, hash, and row count.
3. Run `npm --prefix web run generate:operator-names`.
4. Run `npm --prefix web run check`.
5. Run `node --test web/scripts/diagnostic-values.test.mjs`.
6. Run `npm --prefix web run build` and inspect the package size.

The generator accepts only exact MCC/MNC strings.
It preserves leading zeroes.
Unknown, malformed, and already named values remain unchanged.
The `46697` entry has a Traditional Chinese and Simplified Chinese label.
Other entries use the source brand as the fallback name.
