# Contributing

Add a `docs/changelog.d/+short-name.<type>.rst` fragment for a change that affects package users. Choose a unique short
name; the release workflow links the fragment to its merged squash pull request and credits the human author. A pull
request number is not needed in the filename.

Use `feature` for Added, `change` for Changes, `bugfix` for Fixed, and `doc` for Documentation. Use `breaking`,
`security`, `performance`, `deprecation`, `removal`, or `packaging` only when the change affects users in that way. A
supported Python version added or removed is a `feature` and results in a minor release.

Use `skip news` for internal maintenance without a user-facing change. The label may be added after opening the pull
request. Dependabot and maintenance bot pull requests without a fragment receive it automatically; a bot pull request
with a fragment still needs the news check to pass. For a change written by more than one person, put all human authors
in a `by` credit. Do not list bots or reviewers.

The documentation preview shows fragments under Unreleased. The versioned `docs/changelog.rst` changes only during
release preparation. The release workflow chooses a version from the fragment types, runs `prek` on the assembled
changelog, and publishes GitHub notes from the tagged changelog after PyPI succeeds.
