# Mintlayer core contributing guide

We are happy to take contributions to the project in any form: if you find a bug feel free to create an issue, 
if you fix a bug feel free to create a pr to merge your fix, if you want to add a totally new feature go ahead and do so.

## Setup

Follow [these instructions](https://www.rust-lang.org/tools/install) to install rust which is required to build Mintlayer.

## How to actually contribute

The first thing to do, once you know what you want to do, is to open an issue. If you think you'd found a bug open an issue so it can be discussed with the wider
community. If you think you've got a snazzy new idea for a feature, open an issue and we'll discuss it as a community; maybe someone else is already working on it...

Whatever it is you're working on you'll want to create a branch for your bug fix or feature from staging
 
 
    git checkout staging
    git checkout -b my_new_branch
   
   
I'd suggest you pick a better name than that though, something which makes it obvious what you're working on is preferred. Once you're done the first step is to make
sure that the existing functional tests and unit tests still work. If you've broken something it's time to go and fix that first. Once the existing tests are good
it's time for you to add your own. Even for small bug fixes adding a unit test is worth the effort to ensure the bug isn't reintroduced later. For new features, functional tests
are a hard requirement. Make life as easy as possible for the reviewer when they have to look at the actual code. What testing have you done? Have you run any benchmarks?

Once you've created a set of tests that prove out your code create a PR to merge your branch into staging. Make sure you write a good PR. Explain what you're doing, 
explain why you're doing it, explain how this interacts with the existing codebase and explain how it works. Make sure to link to the open issue too. When you pick
reviewers GitHub will likely recommend some people. If not tag anyone and they can help get the right people involved. Your code will either be merged or changes will be requested.
Before you open the PR, think about what else you can do to make the reviewer's life easier… Can you run cargo-audit to find known issues in libraries? Could you run a fuzzer or static analyser? Have you checked the licenses of any libraries you’re using?
A good pull request should try and limit the number of lines changed in the request, as a general rule it takes roughly 60 mins to review a 300-400 line request so try and keep PRs to 300-400 lines in total.
A pull request should try and deal with a single issue be it a new feature or a bug fix. If you’re fixing 2 separate unrelated bugs then open 2 PRs. A PR should be made of logical commits, that could be a single commit for a simple bug or several commits for a more complex new feature. If you refactor some existing code and add a new feature in the same PR then that should be at least 2 commits.

## A quick guide to Mintlayer

Mintlayer uses a UTXO system rather than an account-based system.

Mintlayer supports bech32 addresses and our own implementation of Bitcoin script, sometimes called chainscript or mintlayer script.

Mintlayer has a feature known as programmable pools (or PPs). These are essentially Wasm-based smart contracts. As it stands PP support is very much a work in progress.

At the moment Mintlayer uses Schnorr signatures for its base crypto. There is an intention to move to BLS in the near future. We have a BLS implementation ready to go but there is some degree of work to be done to fully integrate it with the existing code base, if you create a new feature try to plan it in a cryptographically agnostic way.
