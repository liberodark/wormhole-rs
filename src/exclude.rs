use std::path::Path;

#[derive(Debug, Clone)]
enum Segment {
    Literal(String),
    Star,
    DoubleStar,
    Question,
    CharClass { negated: bool, chars: Vec<char> },
}

#[derive(Debug, Clone)]
pub struct ExcludePattern {
    anchored: bool,
    dir_only: bool,
    has_slash: bool,
    segments: Vec<Segment>,
}

impl ExcludePattern {
    pub fn new(pattern: &str) -> Self {
        let mut p = pattern;

        let anchored = p.starts_with('/');
        if anchored {
            p = &p[1..];
        }

        let dir_only = p.ends_with('/');
        if dir_only {
            p = &p[..p.len() - 1];
        }

        let has_slash = p.contains('/');
        let segments = parse_segments(p);

        Self {
            anchored,
            dir_only,
            has_slash,
            segments,
        }
    }

    pub fn matches(&self, path: &Path, is_dir: bool) -> bool {
        if self.dir_only && !is_dir {
            return false;
        }

        let path_str = path.to_string_lossy();
        let path_str = path_str.replace('\\', "/");

        if self.anchored || self.has_slash {
            match_segments(&self.segments, &path_str)
        } else {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy())
                .unwrap_or_default();
            match_segments(&self.segments, &name)
        }
    }
}

fn parse_segments(pattern: &str) -> Vec<Segment> {
    let mut segments = Vec::new();
    let mut chars = pattern.chars().peekable();
    let mut literal = String::new();

    while let Some(c) = chars.next() {
        match c {
            '*' => {
                if !literal.is_empty() {
                    segments.push(Segment::Literal(std::mem::take(&mut literal)));
                }
                if chars.peek() == Some(&'*') {
                    chars.next();
                    if chars.peek() == Some(&'/') {
                        chars.next();
                    }
                    segments.push(Segment::DoubleStar);
                } else {
                    segments.push(Segment::Star);
                }
            }
            '?' => {
                if !literal.is_empty() {
                    segments.push(Segment::Literal(std::mem::take(&mut literal)));
                }
                segments.push(Segment::Question);
            }
            '[' => {
                if !literal.is_empty() {
                    segments.push(Segment::Literal(std::mem::take(&mut literal)));
                }
                let negated = chars.peek() == Some(&'!');
                if negated {
                    chars.next();
                }
                let mut class_chars = Vec::new();
                for cc in chars.by_ref() {
                    if cc == ']' {
                        break;
                    }
                    class_chars.push(cc);
                }
                segments.push(Segment::CharClass {
                    negated,
                    chars: class_chars,
                });
            }
            '\\' => {
                if let Some(escaped) = chars.next() {
                    literal.push(escaped);
                }
            }
            _ => literal.push(c),
        }
    }

    if !literal.is_empty() {
        segments.push(Segment::Literal(literal));
    }

    segments
}

fn match_segments(segments: &[Segment], text: &str) -> bool {
    match_recursive(segments, text, 0)
}

fn match_recursive(segments: &[Segment], text: &str, seg_idx: usize) -> bool {
    if seg_idx >= segments.len() {
        return text.is_empty();
    }

    match &segments[seg_idx] {
        Segment::Literal(lit) => {
            if let Some(rest) = text.strip_prefix(lit.as_str()) {
                match_recursive(segments, rest, seg_idx + 1)
            } else {
                false
            }
        }
        Segment::Star => {
            for i in 0..=text.len() {
                let prefix = &text[..i];
                if prefix.contains('/') {
                    break;
                }
                if match_recursive(segments, &text[i..], seg_idx + 1) {
                    return true;
                }
            }
            false
        }
        Segment::DoubleStar => {
            for i in 0..=text.len() {
                if match_recursive(segments, &text[i..], seg_idx + 1) {
                    return true;
                }
            }
            false
        }
        Segment::Question => {
            let mut chars = text.chars();
            if let Some(c) = chars.next()
                && c != '/'
            {
                return match_recursive(segments, chars.as_str(), seg_idx + 1);
            }
            false
        }
        Segment::CharClass { negated, chars } => {
            let mut text_chars = text.chars();
            if let Some(c) = text_chars.next() {
                let in_class = chars.contains(&c);
                let matched = if *negated { !in_class } else { in_class };
                if matched && c != '/' {
                    return match_recursive(segments, text_chars.as_str(), seg_idx + 1);
                }
            }
            false
        }
    }
}

pub fn compile_patterns(patterns: &[String]) -> Vec<ExcludePattern> {
    patterns.iter().map(|p| ExcludePattern::new(p)).collect()
}

pub fn is_excluded(path: &Path, is_dir: bool, patterns: &[ExcludePattern]) -> bool {
    patterns.iter().any(|p| p.matches(path, is_dir))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn test_simple_wildcard() {
        let pat = ExcludePattern::new("*.log");
        assert!(pat.matches(&p("test.log"), false));
        assert!(pat.matches(&p("foo/test.log"), false));
        assert!(!pat.matches(&p("test.txt"), false));
    }

    #[test]
    fn test_double_star() {
        let pat = ExcludePattern::new("**/cache");
        assert!(pat.matches(&p("cache"), true));
        assert!(pat.matches(&p("foo/cache"), true));
        assert!(pat.matches(&p("foo/bar/cache"), true));
    }

    #[test]
    fn test_anchored() {
        let pat = ExcludePattern::new("/build");
        assert!(pat.matches(&p("build"), true));
        assert!(!pat.matches(&p("src/build"), true));
    }

    #[test]
    fn test_dir_only() {
        let pat = ExcludePattern::new("cache/");
        assert!(pat.matches(&p("cache"), true));
        assert!(!pat.matches(&p("cache"), false));
    }

    #[test]
    fn test_path_pattern() {
        let pat = ExcludePattern::new("foo/bar");
        assert!(pat.matches(&p("foo/bar"), false));
        assert!(!pat.matches(&p("baz/foo/bar"), false));
    }

    #[test]
    fn test_question_mark() {
        let pat = ExcludePattern::new("test?.log");
        assert!(pat.matches(&p("test1.log"), false));
        assert!(pat.matches(&p("testA.log"), false));
        assert!(!pat.matches(&p("test.log"), false));
        assert!(!pat.matches(&p("test12.log"), false));
    }

    #[test]
    fn test_char_class() {
        let pat = ExcludePattern::new("[abc].txt");
        assert!(pat.matches(&p("a.txt"), false));
        assert!(pat.matches(&p("b.txt"), false));
        assert!(!pat.matches(&p("d.txt"), false));
    }

    #[test]
    fn test_negated_char_class() {
        let pat = ExcludePattern::new("[!abc].txt");
        assert!(!pat.matches(&p("a.txt"), false));
        assert!(pat.matches(&p("d.txt"), false));
    }

    #[test]
    fn test_star_no_slash() {
        let pat = ExcludePattern::new("a*b");
        assert!(pat.matches(&p("ab"), false));
        assert!(pat.matches(&p("aXXXb"), false));
        assert!(!pat.matches(&p("a/b"), false));
    }

    #[test]
    fn test_nested_double_star() {
        let pat = ExcludePattern::new("foo/**/bar");
        assert!(pat.matches(&p("foo/bar"), false));
        assert!(pat.matches(&p("foo/x/bar"), false));
        assert!(pat.matches(&p("foo/x/y/bar"), false));
        assert!(!pat.matches(&p("bar"), false));
    }

    #[test]
    fn test_is_excluded() {
        let patterns = compile_patterns(&[
            "*.log".to_string(),
            "target/".to_string(),
            ".git/".to_string(),
        ]);
        assert!(is_excluded(&p("test.log"), false, &patterns));
        assert!(is_excluded(&p("target"), true, &patterns));
        assert!(is_excluded(&p(".git"), true, &patterns));
        assert!(!is_excluded(&p("src/main.rs"), false, &patterns));
    }

    #[test]
    fn test_game_files() {
        let pat = ExcludePattern::new("game.*");
        assert!(pat.matches(&p("game.dat"), false));
        assert!(pat.matches(&p("game.dat-shm"), false));
        assert!(pat.matches(&p("game.dat-wal"), false));
        assert!(pat.matches(&p("foo/game.dat"), false));
        assert!(pat.matches(&p("foo/bar/game.dat"), false));
    }
}
