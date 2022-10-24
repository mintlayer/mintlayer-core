#[macro_export]
macro_rules! make_config_setting {
    ($name:ident, $tp: ident, $default_value:expr) => {
        #[derive(Debug)]
        pub struct $name {
            value: $tp,
        }

        impl From<$tp> for $name {
            fn from(v: $tp) -> Self {
                Self { value: v }
            }
        }

        impl From<Option<$tp>> for $name {
            fn from(v: Option<$tp>) -> Self {
                Self {
                    value: v.unwrap_or(Self::default().value),
                }
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self {
                    value: $default_value,
                }
            }
        }

        impl std::ops::Deref for $name {
            type Target = $tp;

            fn deref(&self) -> &Self::Target {
                &self.value
            }
        }

        impl AsRef<$tp> for $name {
            fn as_ref(&self) -> &$tp {
                &self.value
            }
        }
    };
}
