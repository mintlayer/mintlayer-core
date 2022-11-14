use logging::log;

use super::memsize::MemSize;

#[must_use]
pub struct MapResizeInfo {
    current_size: MemSize,
    required_size: MemSize,
}

impl MapResizeInfo {
    pub fn from_resize_headroom(
        env: &lmdb::Environment,
        headroom: MemSize,
        do_log: bool,
    ) -> storage_core::Result<Self> {
        // Get page size
        let page_size = {
            let stat = env.stat().or_else(crate::error::process_with_err)?;
            MemSize::from_bytes(stat.page_size() as u64)
        };

        // Get current occupancy info
        let info = env.info().or_else(crate::error::process_with_err)?;
        let current_size = MemSize::from_bytes(info.map_size() as u64);
        let current_pages = current_size.div_ceil(page_size);
        let used_pages = (info.last_pgno() + 1) as u64;
        let freelist_pages = env.freelist().or_else(crate::error::process_with_err)? as u64;
        let free_pages = (current_pages - used_pages) + freelist_pages;

        // Get map size requirements
        let required_free_pages = headroom.div_ceil(page_size);
        let required_pages = used_pages + required_free_pages;
        let required_size = required_pages * page_size;

        if do_log {
            log::trace!(
                "LMDB memory: occupied = {} - {}, reserved = {}, free = {}, required = {}",
                used_pages * page_size,
                freelist_pages * page_size,
                current_size,
                free_pages * page_size,
                required_size,
            );
        }

        let result = Self {
            current_size,
            required_size,
        };

        Ok(result)
    }

    pub fn should_resize_map(&self) -> bool {
        self.required_size > self.current_size
    }

    pub fn current_size(&self) -> MemSize {
        self.current_size
    }

    pub fn required_size(&self) -> MemSize {
        self.required_size
    }
}
