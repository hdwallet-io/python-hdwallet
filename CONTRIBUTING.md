# Contributing to HDWallet

First off, thanks for taking the time to contribute and
when contributing to this repository, please first discuss 
the change you wish to make via [issue](https://github.com/hdwallet-io/hdwallet/issues) 
with the owners of this repository before making a change.

## Development

### Using Nix (Recommended)

The easiest way to get a complete development environment is to use Nix. This approach provides the correct Python version and all dependencies automatically.

If you have Nix installed, you can get a full development/runtime environment by running:

```
make nix-venv
```

This will activate an interactive shell with the Nix environment and Python virtual environment set up.

To run specific commands in the Nix + venv environment, use the pattern `make nix-venv-target`:

```
make nix-venv-test        # Run tests in Nix + venv environment
make nix-venv-install     # Install package in Nix + venv environment
```

### Manual Setup

Alternatively, you can set up the development environment manually. Fork this repo, clone it locally, and run:

```
pip install -e .[cli,tests,docs]
```

## Pull Request

Add notes for pushing your branch:

> When you are ready to generate a pull request, either for preliminary review, 
or for consideration of merging into the project you must first push your local 
topic branch back up to GitHub.

Include a note about submitting the PR:

> Once you've committed and pushed all of your changes to GitHub, go to the page 
for your fork on GitHub, select your development branch, and click the pull request 
button. If you need to make any adjustments to your pull request, just push the updates 
to your branch. Your pull request will automatically track the changes on your 
development branch and update.

```commandline
git push origin new-feature
```

- Fork the repository and make a branch for your translation.
- Ensure any install or build dependencies are removed before the end of the layer when doing a build.
- Include any relevant documentation updates

GitHub's documentation for working on pull requests is [available here](https://help.github.com/articles/about-pull-requests).

## Testing

You can run the tests with:

```
coverage run -m pytest
```

To see the coverage:

```
coverage report
```

Or use `tox` to run the complete suite against the full set of build targets, or pytest to run specific 
tests against a specific version of Python.

## License

Distributed under the [MIT](https://github.com/hdwallet-io/python-hdwallet/blob/master/LICENSE) license. See ``LICENSE`` for more information.
