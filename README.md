<p align="center">
    <a href="https://github.com/lupaxa-miscellaneous-toolbox">
        <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/organisations/miscellaneous-toolbox/readme-logo.png" alt="Miscellaneous Toolbox" />
    </a>
</p>

<h1 align="center">Metadata Inspector</h1>

Metadata Inspector is an offline command-line utility for photographic
images. It inspects embedded metadata, identifies privacy-sensitive fields,
explains them, writes cleaned copies, and verifies that cleaning succeeded.

It is meant for individual photographs and for directories. Photographs and
extracted metadata stay on the machine that runs the command. Nothing is
uploaded, and coordinates are not sent to a mapping service.

> **Note:** Removing metadata does not remove identifying information that
> is visible in the photograph. Metadata Inspector does not anonymise image
> content. A classification describes the metadata that was found. It does
> not prove that a privacy breach has occurred. Matching metadata is not
> proof that two photographs came from the same device or the same person.

## Install

Python 3.11 or newer. The PyPI package name is `lupaxa-metadata-inspector`.
The console command is `metadata-inspector`.

```bash
python -m pip install lupaxa-metadata-inspector
```

HEIC and HEIF inspection needs the optional extra. Cleaning those formats
stays disabled.

```bash
python -m pip install "lupaxa-metadata-inspector[heif]"
```

From a clone, for development:

```bash
python -m pip install -e ".[dev]"
```

The same commands work as a module:

```bash
python -m lupaxa.metadata_inspector version
```

## Commands

A directory command looks at `jpg`, `jpeg`, `png`, `webp`, `tif`, `tiff`,
`heic`, and `heif` unless you pass `--extensions`.

| Command    | What it Does                                                                                                     |
| :--------: | :--------------------------------------------------------------------------------------------------------------: |
| `scan`     | Inspect files or a directory and print the findings.                                                             |
| `show`     | List metadata for one file, grouped by family, with the stored value and a readable form.                        |
| `explain`  | Add the classification, what the field means, and what a profile would do with it.                               |
| `clean`    | Write a sibling named with `-clean`. The original bytes stay unchanged.                                          |
| `verify`   | Check a cleaned file, or an original and the cleaned copy. The check is independent of the cleaner's own report. |
| `compare`  | List exact matches and different values between two photographs. A match is not identity.                        |
| `report`   | Write the same inspection as `scan` to a file. `--output` is the report, not an image.                           |
| `check`    | Exit 3 when the profile would still remove something. The default profile is `public`.                           |
| `formats`  | Show which formats this installation can inspect, clean, and verify.                                             |
| `profiles` | List profiles. `profiles show public` prints one profile and the preserve rules.                                 |
| `version`  | Print the application version and the Python backend.                                                            |

```bash
metadata-inspector scan photo.jpg
metadata-inspector explain photo.jpg --field exif.gps.coordinates
metadata-inspector clean photo.jpg
metadata-inspector verify photo.jpg photo-clean.jpg
metadata-inspector report photos/ --format html --output report.html
```

## Options

Shared options work on every command. The command column names the commands
where that option changes the result.

| Option                | Commands                           | What it Does                                                                          |
| :-------------------: | :--------------------------------: | :-----------------------------------------------------------------------------------: |
| `--recursive`, `-r`   | `scan`, `clean`, `report`, `check` | Walk subdirectories.                                                                  |
| `--extensions`        | `scan`, `clean`, `report`, `check` | Comma-separated extensions to include.                                                |
| `--hidden`            | `scan`, `clean`, `report`, `check` | Include names that start with a dot.                                                  |
| `--follow-symlinks`   | `scan`, `clean`, `report`, `check` | Read the target of a symbolic link. Off by default.                                   |
| `--workers`           | `scan`, `report`, `check`          | How many files to inspect at once. Default is 4.                                      |
| `--max-size`          | any inspection                     | Skip a file larger than this many bytes. Default is 100 megabytes.                    |
| `--format`            | `scan`, `report`                   | `text`, `json`, `markdown`, `html`, or `csv`. HTML is one self-contained file.        |
| `--json`              | any command                        | Print JSON. Same result as `--format json`. Progress and errors go to stderr.         |
| `--json-lines`        | `scan`, `report`                   | Print one JSON object per line.                                                       |
| `--output`, `-o`      | `clean`, `report`                  | Cleaned image or directory, or the report path.                                       |
| `--profile`           | `clean`, `verify`, `check`         | Profile name. Overrides `default_profile` in the config file.                         |
| `--config`            | any command                        | TOML file. It wins over the user config file.                                         |
| `--reveal`            | any command that prints values     | Show GPS coordinates and serial numbers.                                              |
| `--verbose`, `-v`     | any command                        | Print progress on stderr. Exit 2 when combined with `--quiet`.                        |
| `--quiet`, `-q`       | any command                        | Omit the text report. JSON still prints.                                              |
| `--no-colour`         | text output                        | Turn colour off. Also off when `NO_COLOR` is set, or when stdout is not a terminal.   |
| `--version`           | top level                          | Print the version and exit.                                                           |
| `--family`            | `show`                             | Show one metadata family, such as `GPS` or `EXIF`.                                    |
| `--field`             | `explain`                          | Explain one field id, name, or tag.                                                   |
| `--dry-run`           | `clean`                            | Plan the clean and write nothing.                                                     |
| `--suffix`            | `clean`                            | Text inserted before the extension. Default is `-clean`.                              |
| `--force`             | `clean`                            | Replace an output file that already exists.                                           |
| `--in-place`          | `clean`                            | Replace the original. A `name.bak` copy is kept.                                      |
| `--no-backup`         | `clean`                            | With `--in-place`, do not write `name.bak`.                                           |
| `--apply-orientation` | `clean`                            | Rotate the pixels to match the orientation tag, then re-encode.                       |
| `--fail-on`           | `check`                            | Also fail at this classification or higher: `high`, `medium`, `low`, `informational`. |

## Profiles

Preserve rules win over remove rules. Orientation stays when
`preserve_orientation` is true. ICC profiles stay when `preserve_icc` is
true. Copyright and attribution stay when `preserve_copyright` is true, even
if that classification would otherwise be removed. No profile makes a
photograph anonymous.

| Profile     | What it Removes                                                                                      |
| :---------: | :--------------------------------------------------------------------------------------------------: |
| `metadata`  | High, medium, low, and informational metadata. Attribution is removed.                               |
| `public`    | High and medium findings, including GPS and serial numbers. Attribution stays. This is the default.  |
| `anonymous` | High, medium, and low findings, including attribution. The image content can still identify someone. |
| `minimal`   | High through informational, including attribution. Orientation and ICC stay.                         |

Built-in profiles keep orientation and ICC data, remove embedded previews,
and use strict verification. They cannot be replaced in a config file.

A custom profile lives under `[profiles.name]` in TOML. Useful keys are
`remove_classifications`, `remove_families`, `remove_tags`, `preserve_tags`,
`preserve_copyright`, `preserve_orientation`, `preserve_icc`,
`remove_thumbnails`, and `strict`.

On macOS the user file is
`~/Library/Application Support/metadata-inspector/config.toml`. On Linux it
is `$XDG_CONFIG_HOME/metadata-inspector/config.toml`, or
`~/.config/metadata-inspector/config.toml`. On Windows it is
`%APPDATA%\metadata-inspector\config.toml`. An explicit `--config` file wins
over the user file. Command-line `--profile` wins over `default_profile`.

## Classification

Findings are `high`, `medium`, `low`, or `informational`.

GPS coordinates, serial numbers, and owner names are high. Timestamps, lens
details, and place names are typically medium. Camera make, model, and
software are low. Copyright, orientation, and image dimensions are
informational. A field with no separate privacy rule is informational too.
A normal scan lists high, medium, and low findings. Informational fields
appear with `--verbose`.

GPS coordinates and serial numbers are shown as `[redacted]` unless you pass
`--reveal` or set `redact = false`. A timestamp with no timezone offset is
not treated as UTC. A filesystem modification time is local time for this
computer. It is never removed, because it is not inside the photograph.

## JSON Output

Scan and report JSON uses schema version `1.0`:

```json
{
  "schema_version": "1.0",
  "results": []
}
```

Each result includes `file`, `format`, `inspection_status`, `backend`,
dimensions, `families`, `findings`, `summary`, `limitations`, `errors`, and
`disclaimer`. A finding includes `id`, `name`, `family`, `field`, `tag`,
`classification`, `value`, `redacted`, `explanation`, and `action`.

## Cleaning and Image Quality

JPEG, PNG, WebP, and TIFF are inspected, cleaned, and verified by the Python
backend. JPEG metadata is rewritten by copying segments. The compressed image
data is copied unchanged, so a normal clean does not recompress the
photograph. PNG chunks, WebP RIFF chunks, and TIFF strips or tiles are copied
the same way.

Before a cleaned file is kept, Metadata Inspector reads it again and compares
decoded pixels with the original. If verification does not pass, the output
is not kept. `--apply-orientation` is the exception: it rotates the pixels
with Pillow and re-encodes the image, so JPEG quality can change. The result
is marked as pixel-modified. Removing a non-default orientation tag without
that flag is refused, because the photograph would display incorrectly.

ICC profiles and the orientation tag are kept by every built-in profile.

## Limitations

HEIC and HEIF can be inspected when `pillow-heif` is installed. Cleaning and
verification of cleaning are disabled, because there is no tested rewriter
that keeps the required image characteristics. The file is not converted to
another format.

ExifTool is reported by `formats` and `version` when it is on `PATH`. It is
not used to inspect or clean. `backend = "exiftool"` is rejected.

AVIF and BigTIFF are reported as unsupported. TIFF IPTC and XMP are not read.
A file that cannot be inspected does not count as clean.

## Exit Codes

| Code | Meaning                                                                   |
| :--: | :-----------------------------------------------------------------------: |
| 0    | The command finished. A scan that finds sensitive metadata still exits 0. |
| 1    | A file could not be read or inspected.                                    |
| 2    | The command line or configuration is invalid.                             |
| 3    | `check` found metadata the profile would remove.                          |
| 4    | Verification failed. No cleaned file was kept.                            |
| 5    | The format or backend is unsupported.                                     |
| 6    | A batch mixed successful files with files that could not be completed.    |

## Troubleshooting

`unknown profile` means the name is not a built-in profile and not defined
in the config file that was loaded.

`verification did not pass, so no output file was kept` means the rewritten
file still contained a prohibited field, or the pixels did not match. The
original is unchanged. Inspect the source with `explain` before trying
another profile.

`symbolic link was not followed` is the default. Pass `--follow-symlinks`
only when you intend to read the target.

`file exceeds the configured maximum size` uses the default of 100 megabytes.
Raise it with `--max-size` or `max_file_size` in the config file.

`output already exists` leaves the previous file in place. Choose another
`--output`, change `--suffix`, or pass `--force`.

## Testing

```bash
make init
make python-install-dev
make python-check
```

Or without Make:

```bash
python -m pip install -e ".[test]"
pytest
```

<a href="https://github.com/the-lupaxa-project">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/components/footer-for-child-orgs.svg" alt="The Lupaxa Project Footer" width="100%" />
</a>
