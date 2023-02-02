use crate::memsize::MemSize;

pub struct InitialMapSize {
    initial_map_size: MemSize,
}

impl InitialMapSize {
    pub fn into_memsize(&self) -> MemSize {
        self.initial_map_size
    }
}

impl Default for InitialMapSize {
    fn default() -> Self {
        Self {
            initial_map_size: MemSize::from_bytes(0),
        }
    }
}

impl From<MemSize> for InitialMapSize {
    fn from(initial_map_size: MemSize) -> Self {
        Self { initial_map_size }
    }
}

impl From<InitialMapSize> for MemSize {
    fn from(initial_map_size: InitialMapSize) -> Self {
        initial_map_size.initial_map_size
    }
}
