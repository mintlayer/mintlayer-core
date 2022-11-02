// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Tools to create fresh temporary directories for testing on demand

use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::random::Seed;
use crypto::random::Rng;

fn backoff_delays(seed: Seed) -> impl Iterator<Item = Duration> {
    // Random exponential backoff starting at 1ms with max 10 attempts
    let mut rng = crate::random::make_seedable_rng(seed);
    let mut delay = Duration::from_millis(1);
    std::iter::from_fn(move || {
        let item = rng.gen_range(Duration::ZERO..delay);
        delay *= 2;
        Some(item)
    })
    .take(10)
}

/// Create a new test root based on `$CARGO_TARGET_TMPDIR/$CARGO_PKG_NAME/$custom_subdirs`
#[macro_export]
macro_rules! test_root {
    ($($dirs:expr),* $(,)?) => {
        $crate::test_dir::TestRoot::create({
            let mut path = ::std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
            path.push(env!("CARGO_PKG_NAME"));
            $(path.push($dirs);)*
            path
        })
    }
}

/// Outcome of an attempt to create a directory
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub enum DirCreationOutcome {
    Created,
    AlreadyExists,
}

/// Create a directory, signalling whether it was created or already existed
pub fn try_create_dir(path: impl AsRef<Path>) -> io::Result<DirCreationOutcome> {
    match fs::create_dir(path.as_ref()) {
        Ok(()) => Ok(DirCreationOutcome::Created),
        Err(e) => match e.kind() {
            std::io::ErrorKind::AlreadyExists => Ok(DirCreationOutcome::AlreadyExists),
            _ => Err(e),
        },
    }
}

/// Root directory for a test run.
///
/// Corresponds to a working directory for a test binary run
#[derive(Clone, Debug)]
pub struct TestRoot(Arc<TestRootImpl>);

impl TestRoot {
    /// Create the root test directory
    pub fn create(top_path: impl AsRef<Path>) -> io::Result<Self> {
        let mut rng = crate::random::make_seedable_rng(Seed::from_entropy());

        // Create the top-level directory if it does not exist already
        fs::create_dir_all(top_path.as_ref())?;

        for delay in backoff_delays(Seed::from_u64(rng.gen())) {
            let path = top_path.as_ref().join(format!("run_{:08x}", rng.gen::<u32>()));

            // Attempt to create the candidate directory
            match try_create_dir(&path)? {
                DirCreationOutcome::Created => {
                    // Successfully created
                    let counter = AtomicU32::new(0);
                    return Ok(Self(Arc::new(TestRootImpl { path, counter })));
                }
                DirCreationOutcome::AlreadyExists => {
                    // If directory already exists, continue the loop to try again.
                    std::thread::sleep(delay);
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "All attempted directory names exist",
        ))
    }

    /// Create the new test subdirectory
    pub fn fresh_test_dir(&self, name: impl AsRef<str>) -> TestDir {
        let seq_no = self.0.counter.fetch_add(1, Ordering::SeqCst);
        let name = name.as_ref().replace(['/', ':', '\\'], "_");
        let path = self.0.path.join(format!("case_{:08x}_{}", seq_no, name));
        fs::create_dir(&path).expect("directory creation to succeed");
        TestDir { path }
    }

    /// Delete the directory. Panics if it is still in use.
    pub fn delete(self) {
        let inner = Arc::try_unwrap(self.0).expect("Test root still in use");
        if let Err(err) = fs::remove_dir_all(&inner.path) {
            eprintln!("Failed to remove test dir {:?}: {}", &inner.path, err);
        }
    }
}

#[derive(Debug)]
struct TestRootImpl {
    path: PathBuf,
    counter: AtomicU32,
}

/// Represents a test directory.
#[derive(Debug)]
pub struct TestDir {
    path: PathBuf,
}

impl AsRef<Path> for TestDir {
    fn as_ref(&self) -> &Path {
        self.path.as_ref()
    }
}
