use std::{fs::File, path::PathBuf, sync::Arc};

pub(super) fn exec_path(_file: &Arc<File>) -> Option<PathBuf> {
    None
}
pub(super) fn exec_identity(_pid: u32) -> Option<(u64, u64)> {
    None
}
