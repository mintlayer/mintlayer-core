# Mintlayer core contributing guide

## General

If you want to contribute but have no idea what to start working on, feel free to check the [issues](https://github.com/mintlayer/mintlayer-core/issues) or grep for "TODO" in the code. If you have a proposal for a major change or feature that we haven't outlined before, the best idea would be to open an issue or pull request to discuss the idea before you delve too deeply into it, as there may be a good reason we haven't gone that route before.

If you find a security issue, please follow the guide [here](https://github.com/mintlayer/mintlayer-core/security/policy) to report it.

## External contributors

First and foremost, you should make sure you have [rust installed](https://www.rust-lang.org/tools/install). As a rule, we use the latest stable version of rust that is available; if this changes, we'll be sure to update this note.

As an outside contributor, your first step will be to fork the repo and create your own copy. You can't push to our repo directly, so without doing this, it won't be possible to contribute any code. Your contributions should be put in a logically named branch in your fork. If you're not sure what I mean by that, take a look at the extant branches in our repo, and you'll see some examples. If you have several significant changes to make that don't logically fit together, then multiple branches and pull requests are the way to go.

As you make your changes, ensure the code is as clean as possible and well documented so that it's clear to us what you're up to when we review it and it is thoroughly tested. Make sure that the old tests still pass, as well as any tests you've added. We will only merge code with all the tests passing in CI.

## Internal contributors

By internal contributors, we mean people who are members of the Mintlayer organization. If you are not employed full-time to work on Mintlayer but have substantial contributions, drop us a message, and we'll see what can be done about adding you.

Internal contributors don't need to worry about the above guide too much, the general bits about rust apply, but you can clone the repo and push branches directly. By default, you can't push to the master branch (and those who can should avoid it). When you create a pull request, it will automatically add the core repo maintainers as reviewers, don't feel like this is a complete list; if you think a review from someone else is handy, then add them; you won't be able to merge without a maintainer's approval though and preferably the approval of multiple. The CI will run automatically on your PRs, too, and you won't be able to merge without it passing. As a rule, a draft PR is always welcome as it will get feedback quicker, be sure to mark it as such.
