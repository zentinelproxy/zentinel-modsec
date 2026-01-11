//! Transformation pipeline.

use super::{create_transformation, Transformation};
use crate::error::Result;
use std::borrow::Cow;
use std::sync::Arc;

/// A pipeline of transformations to apply in sequence.
#[derive(Clone)]
pub struct TransformationPipeline {
    transformations: Vec<Arc<dyn Transformation>>,
}

impl TransformationPipeline {
    /// Create an empty pipeline.
    pub fn new() -> Self {
        Self {
            transformations: Vec::new(),
        }
    }

    /// Create a pipeline from transformation names.
    pub fn from_names(names: &[String]) -> Result<Self> {
        let mut transformations = Vec::new();

        for name in names {
            // Handle "none" specially - it clears the pipeline
            if name.eq_ignore_ascii_case("none") {
                transformations.clear();
                continue;
            }

            let t = create_transformation(name)?;
            transformations.push(t);
        }

        Ok(Self { transformations })
    }

    /// Add a transformation to the pipeline.
    pub fn add(&mut self, transformation: Arc<dyn Transformation>) {
        self.transformations.push(transformation);
    }

    /// Apply all transformations in sequence.
    pub fn apply<'a>(&self, input: &'a str) -> Cow<'a, str> {
        if self.transformations.is_empty() {
            return Cow::Borrowed(input);
        }

        let mut current: Cow<str> = Cow::Borrowed(input);

        for t in &self.transformations {
            current = match current {
                Cow::Borrowed(s) => t.transform(s),
                Cow::Owned(s) => {
                    let transformed = t.transform(&s);
                    match transformed {
                        Cow::Borrowed(_) => Cow::Owned(s),
                        Cow::Owned(new) => Cow::Owned(new),
                    }
                }
            };
        }

        current
    }

    /// Check if the pipeline is empty.
    pub fn is_empty(&self) -> bool {
        self.transformations.is_empty()
    }

    /// Get the number of transformations.
    pub fn len(&self) -> usize {
        self.transformations.len()
    }
}

impl Default for TransformationPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for TransformationPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransformationPipeline")
            .field(
                "transformations",
                &self
                    .transformations
                    .iter()
                    .map(|t| t.name())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_pipeline() {
        let pipeline = TransformationPipeline::new();
        assert_eq!(pipeline.apply("hello"), "hello");
    }

    #[test]
    fn test_single_transformation() {
        let pipeline =
            TransformationPipeline::from_names(&["lowercase".to_string()]).unwrap();
        assert_eq!(pipeline.apply("HELLO"), "hello");
    }

    #[test]
    fn test_multiple_transformations() {
        let pipeline = TransformationPipeline::from_names(&[
            "urlDecode".to_string(),
            "lowercase".to_string(),
        ])
        .unwrap();
        assert_eq!(pipeline.apply("HELLO%20WORLD"), "hello world");
    }

    #[test]
    fn test_none_clears_pipeline() {
        let pipeline = TransformationPipeline::from_names(&[
            "lowercase".to_string(),
            "none".to_string(),
            "uppercase".to_string(),
        ])
        .unwrap();
        // Only uppercase should be applied
        assert_eq!(pipeline.apply("hello"), "HELLO");
    }
}
