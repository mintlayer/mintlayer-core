// Copyright (c) 2021-2023 RBB S.r.l
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

//! The enrichment root span: a span that stays entered for the whole process and carries
//! the fields every log line should show.

use std::{borrow::Cow, sync::OnceLock};

use tracing::{
    Level, Span,
    callsite::{Callsite, Identifier},
    field::{FieldSet, Value},
    metadata::{Kind, Metadata},
    subscriber::Interest,
};

/// The name of the enrichment root span.
const ROOT_SPAN_NAME: &str = "node";

/// The field names that [`enter_root_span`] records itself; extra fields with these names
/// are ignored.
const BUILT_IN_FIELDS: [&str; 3] = ["version", "chain", "pid"];

static ROOT_SPAN: OnceLock<Span> = OnceLock::new();

/// Enters the enrichment root span, which stays entered for the rest of the process.
///
/// The span is named "node" and carries the `version`, `chain` and `pid` fields plus one
/// field per `extra_fields` entry (string values; the first occurrence of a repeated name
/// wins and the built-in names are reserved). Every event emitted while the span is current
/// carries the fields: in the json output as the first element of `spans`, in the text
/// output as a `node{...}` prefix in front of the target. The span is created at the INFO
/// level under the `logging::enrichment` target, so a sink whose filter disables that
/// target (for example `RUST_LOG=logging::enrichment=off`) does not show the prefix.
///
/// This must be called after logging is initialized (the span is created by the subscriber
/// that is current at the time of the first call) and only the first call has an effect.
///
/// The entered guard is leaked on purpose: dropping it would exit the span, and the span
/// has to stay entered and alive for the whole process. The leak is a single, bounded
/// allocation, since the span is entered once at startup.
///
/// Note that an entered span only applies to the calling thread. The node enters the span
/// on its main thread before its subsystems are started, and the subsystem crate starts
/// subsystem tasks and runs calls into them inside the span that is current at that point,
/// so their events (emitted on the tokio worker threads) carry the enrichment as well. Only
/// events on threads that are started outside of that instrumentation, such as a plain
/// `tokio::spawn` or a blocking task, do not carry the span.
pub fn enter_root_span(
    version: impl Into<Cow<'static, str>>,
    chain: impl Into<Cow<'static, str>>,
    pid: u32,
    extra_fields: Vec<(String, String)>,
) {
    ROOT_SPAN.get_or_init(|| {
        let span = make_root_span(version.into(), chain.into(), pid, extra_fields);
        std::mem::forget(span.enter());
        span
    });
}

/// The callsite of the root span.
///
/// The metadata is built at runtime and therefore owned by the callsite; the [`OnceLock`]
/// breaks the cycle between the metadata (which names the callsite in its field set) and
/// the callsite (which has to return the metadata).
#[derive(Default)]
struct RootCallsite {
    metadata: OnceLock<Metadata<'static>>,
}

impl Callsite for RootCallsite {
    fn set_interest(&self, _interest: Interest) {
        // The span is created directly, so its interest is never queried.
    }

    fn metadata(&self) -> &Metadata<'_> {
        self.metadata
            .get()
            .expect("the root span callsite metadata is set before the span is created")
    }
}

/// Creates the enrichment root span (see [`enter_root_span`]) without entering it.
fn make_root_span(
    version: Cow<'static, str>,
    chain: Cow<'static, str>,
    pid: u32,
    extra_fields: Vec<(String, String)>,
) -> Span {
    // The span metadata is `'static`, so the callsite and the field names are leaked: they
    // have to live exactly as long as the span, that is, for the rest of the process.
    let callsite: &'static RootCallsite = Box::leak(Box::default());
    let mut names: Vec<&'static str> = BUILT_IN_FIELDS.to_vec();
    for (name, _) in &extra_fields {
        let is_known = names.contains(&name.as_str());
        if !name.is_empty() && !is_known {
            names.push(Box::leak(name.clone().into_boxed_str()));
        }
    }
    let names: &'static [&'static str] = Box::leak(names.into_boxed_slice());
    // This is what the `identify_callsite!` macro of `tracing-core` expands to; the macro
    // itself is only reachable through a direct dependency on that crate.
    let callsite_id = Identifier(callsite);
    callsite
        .metadata
        .set(Metadata::new(
            ROOT_SPAN_NAME,
            module_path!(),
            Level::INFO,
            None,
            None,
            None,
            FieldSet::new(names, callsite_id),
            Kind::SPAN,
        ))
        .expect("the root span callsite metadata is set only once");
    let metadata = callsite.metadata.get().expect("the metadata was set just above");
    // Ask the subscriber whether it enables the span before creating it, like the `span!`
    // macro does through callsite registration: apart from skipping a span no sink wants,
    // this is what records, per layer, whether its filter enabled the span, which is what
    // the fmt layers consult when listing the spans in scope of an event.
    if !tracing::dispatcher::get_default(|dispatch| dispatch.enabled(metadata)) {
        return Span::none();
    }

    // The values are listed in the order of the field names, one per field.
    let version: &str = version.as_ref();
    let chain: &str = chain.as_ref();
    let value_of = |name: &str| -> &dyn Value {
        match name {
            "version" => &version,
            "chain" => &chain,
            "pid" => &pid,
            _ => {
                &extra_fields
                    .iter()
                    .find(|(extra_name, _)| extra_name == name)
                    .expect("every other field name comes from the extra fields")
                    .1
            }
        }
    };
    let values: Vec<Option<&dyn Value>> = names.iter().map(|name| Some(value_of(name))).collect();
    let values = metadata.fields().value_set_all(&values);

    Span::new_root(metadata, &values)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use serde_json::Value as JsonValue;
    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;
    use crate::{
        LogStyle, ValueOrEnvVar, ValueOrEnvVarWithDefault, WriterSettings, make_layer,
        write_to_make_writer,
    };

    /// Collects the output of a subscriber installed for the duration of `capture`.
    #[derive(Clone, Default)]
    struct LogOutput(Arc<Mutex<Vec<u8>>>);

    impl LogOutput {
        fn capture<R>(&self, log_style: LogStyle, f: impl FnOnce() -> R) -> String {
            let mut errors = Vec::new();
            let layer = make_layer(
                WriterSettings {
                    make_writer: write_to_make_writer(self.clone()),
                    is_terminal: false,
                    filter: ValueOrEnvVarWithDefault::Value("trace".to_owned()),
                    log_style: ValueOrEnvVar::Value(log_style),
                    source_location: false,
                    thread_info: false,
                },
                &mut errors,
            );
            assert!(errors.is_empty(), "unexpected log init errors: {errors:?}");

            let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
            tracing::subscriber::with_default(subscriber, f);
            self.take()
        }

        fn take(&self) -> String {
            let mut vec = self.0.lock().unwrap();
            String::from_utf8(std::mem::take(&mut *vec)).unwrap()
        }
    }

    impl std::io::Write for LogOutput {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn make_test_root_span(extra_fields: Vec<(&str, &str)>) -> Span {
        make_root_span(
            "1.5.0".into(),
            "mainnet".into(),
            42,
            extra_fields
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
        )
    }

    #[test]
    fn json_output_carries_the_root_span_fields() {
        let output = LogOutput::default();
        let json = output.capture(LogStyle::Json, || {
            let root_span = make_test_root_span(vec![("role", "seed")]);
            let _guard = root_span.enter();
            tracing::info!("block processed");
        });

        let event: JsonValue = serde_json::from_str(json.trim()).unwrap();
        assert_eq!(event["fields"]["message"], "block processed");
        let spans = event["spans"].as_array().unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0]["name"], "node");
        assert_eq!(spans[0]["version"], "1.5.0");
        assert_eq!(spans[0]["chain"], "mainnet");
        // The pid is recorded as a number, not as a string.
        assert_eq!(spans[0]["pid"], 42);
        assert_eq!(spans[0]["role"], "seed");
    }

    #[test]
    fn text_output_has_the_root_span_prefix() {
        let output = LogOutput::default();
        let text = output.capture(LogStyle::Text(crate::TextColoring::Off), || {
            let root_span = make_test_root_span(vec![("role", "seed")]);
            let _guard = root_span.enter();
            tracing::info!("block processed");
        });

        assert!(
            text.contains(
                " INFO node{version=\"1.5.0\" chain=\"mainnet\" pid=42 role=\"seed\"}: \
                 logging::enrichment::tests: block processed"
            ),
            "{text}"
        );
        // Plain text, no ansi escapes even for the span prefix.
        assert!(!text.contains('\x1b'), "{text}");
    }

    #[test]
    fn extra_fields_do_not_override_built_in_or_earlier_fields() {
        let output = LogOutput::default();
        let json = output.capture(LogStyle::Json, || {
            let root_span = make_test_root_span(vec![
                ("version", "0.0.1"),
                ("role", "first"),
                ("role", "second"),
                ("", "ignored"),
            ]);
            let _guard = root_span.enter();
            tracing::info!("hello");
        });

        let event: JsonValue = serde_json::from_str(json.trim()).unwrap();
        let span = &event["spans"][0];
        assert_eq!(span["version"], "1.5.0");
        assert_eq!(span["role"], "first");
        assert_eq!(span.as_object().unwrap().len(), 5, "{span}");
    }

    #[test]
    fn enter_root_span_is_idempotent() {
        let output = LogOutput::default();
        let json = output.capture(LogStyle::Json, || {
            enter_root_span("1.5.0", "mainnet", 42, Vec::new());
            // A second call must not enter the span again (no nested `node` spans).
            enter_root_span("0.0.0", "othernet", 1, Vec::new());
            tracing::info!("hello");
        });

        let event: JsonValue = serde_json::from_str(json.trim()).unwrap();
        let spans = event["spans"].as_array().unwrap();
        assert_eq!(spans.len(), 1, "{json}");
        assert_eq!(spans[0]["version"], "1.5.0");
        assert_eq!(spans[0]["chain"], "mainnet");
    }

    /// A sink can drop the prefix by filtering out the span's target.
    #[test]
    fn filter_can_disable_the_root_span_for_a_sink() {
        let output = LogOutput::default();
        let mut errors = Vec::new();
        let layer = make_layer(
            WriterSettings {
                make_writer: write_to_make_writer(output.clone()),
                is_terminal: false,
                filter: ValueOrEnvVarWithDefault::Value("info,logging::enrichment=off".to_owned()),
                log_style: ValueOrEnvVar::Value(LogStyle::Text(crate::TextColoring::Off)),
                source_location: false,
                thread_info: false,
            },
            &mut errors,
        );
        assert!(errors.is_empty(), "unexpected log init errors: {errors:?}");

        let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let root_span = make_test_root_span(Vec::new());
            let _guard = root_span.enter();
            // The event target differs from the span target so that only the span is filtered.
            tracing::info!(target: "test_event", "hello");
        });
        let text = output.take();

        assert!(text.contains(" INFO test_event: hello"), "{text}");
        assert!(!text.contains("node{"), "{text}");
    }
}
