use merlin::Transcript;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TranscriptComponent {
    RawData(Vec<u8>),
    U64(u64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranscriptAssembler {
    label: &'static [u8],
    components: Vec<(&'static [u8], TranscriptComponent)>,
}

// A wrapper that makes it unnecessary to use the merlin dependency
pub struct WrappedTranscript(Transcript);

impl From<Transcript> for WrappedTranscript {
    fn from(t: Transcript) -> Self {
        WrappedTranscript(t)
    }
}

impl From<WrappedTranscript> for Transcript {
    fn from(t: WrappedTranscript) -> Self {
        t.0
    }
}

impl TranscriptAssembler {
    pub fn new(label: &'static [u8]) -> Self {
        Self {
            label,
            components: Vec::new(),
        }
    }

    pub fn attach(self, label: &'static [u8], value: TranscriptComponent) -> Self {
        let mut result = self;
        result.components.push((label, value));
        result
    }

    pub fn finalize(self) -> WrappedTranscript {
        let mut transcript = Transcript::new(self.label);
        for component in &self.components {
            match &component.1 {
                TranscriptComponent::RawData(d) => transcript.append_message(component.0, d),
                TranscriptComponent::U64(d) => transcript.append_u64(component.0, *d),
            }
        }

        transcript.into()
    }
}

#[cfg(test)]
mod tests {

    use rand_chacha::ChaChaRng;

    use crate::random::{Rng, SeedableRng};

    use super::*;

    #[test]
    fn manual_vs_assembled() {
        // build first transcript by manually filling values
        let mut manual_transcript = Transcript::new(b"initial");
        manual_transcript.append_message(b"abc", b"xyz");
        manual_transcript.append_u64(b"rx42", 424242);

        // build the second transcript using the assembler
        let assembled_transcript = TranscriptAssembler::new(b"initial")
            .attach(b"abc", TranscriptComponent::RawData(b"xyz".to_vec()))
            .attach(b"rx42", TranscriptComponent::U64(424242))
            .finalize();

        // build a random number generator using each transcript and ensure they both arribe to the same values
        let mut g1 = manual_transcript.build_rng().finalize(&mut ChaChaRng::from_seed([0u8; 32]));
        let mut g2 = assembled_transcript
            .0
            .build_rng()
            .finalize(&mut ChaChaRng::from_seed([0u8; 32]));

        for _ in 0..100 {
            assert_eq!(g1.gen::<u64>(), g2.gen::<u64>());
        }
    }
}
