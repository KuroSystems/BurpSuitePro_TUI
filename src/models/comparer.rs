#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareMode {
    Line,
    Word,
    Binary,
}

impl CompareMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Line => "line diff",
            Self::Word => "word diff",
            Self::Binary => "binary hex diff",
        }
    }

    pub fn next(self) -> Self {
        match self {
            Self::Line => Self::Word,
            Self::Word => Self::Binary,
            Self::Binary => Self::Line,
        }
    }
}
