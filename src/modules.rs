//! Loaded-module filtering used by the terminal module inventory command

use proton_informer_helper_protocol::{ModuleQueryResult, WindowsModuleInfo};

/// Optional filters applied after the helper returns the exact module list
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleFilters {
    /// Case-insensitive substring matched against the module basename only
    pub name: Option<String>,
    /// Case-insensitive substring matched against the module basename or path
    pub contains: Option<String>,
}

impl ModuleFilters {
    /// Returns true when no filter was requested
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.name.is_none() && self.contains.is_none()
    }
}

/// Applies every requested filter while preserving helper target metadata
pub fn apply(result: &mut ModuleQueryResult, filters: &ModuleFilters) {
    if filters.is_empty() {
        return;
    }

    let compiled = CompiledFilters::from(filters);
    result.modules.retain(|module| compiled.matches(module));
}

/// Lower-cased filters avoid repeated string work for every module
struct CompiledFilters {
    name: Option<String>,
    contains: Option<String>,
}

impl CompiledFilters {
    fn matches(&self, module: &WindowsModuleInfo) -> bool {
        let module_name = module.module_name.to_lowercase();

        if let Some(name) = &self.name
            && !module_name.contains(name)
        {
            return false;
        }

        if let Some(contains) = &self.contains {
            let module_path = module.windows_path.to_lowercase();
            if !module_name.contains(contains) && !module_path.contains(contains) {
                return false;
            }
        }

        true
    }
}

impl From<&ModuleFilters> for CompiledFilters {
    fn from(filters: &ModuleFilters) -> Self {
        Self {
            name: filters.name.as_ref().map(|value| value.to_lowercase()),
            contains: filters.contains.as_ref().map(|value| value.to_lowercase()),
        }
    }
}
