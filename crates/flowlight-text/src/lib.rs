//! The sentences Flowlight says, in nine languages.
//!
//! Sentences are most of the interface here. The disclosures are the part somebody agrees to, and an agreement
//! read in a language you are guessing at is not one. So the things a person is asked to consent to — what
//! leaves the machine when export is on, what a question to a model carries, what interception changes, what an
//! address lookup sends — are translated, along with the reasons Flowlight gives for not doing something.
//!
//! # What is here and what is not
//!
//! Disclosures, the reasons attached to them, and the words they are built out of. Not the tables: a column of
//! hosts and byte counts is not a sentence, and a process's name is the process's name in every language.
//!
//! # The catalogue is code
//!
//! One file per language, each a list of pairs, compiled in. Not a `.po` file loaded at runtime, for three
//! reasons: a package can be installed without a file it expected and then has nothing to say; a parser is a
//! dependency and a failure mode for something that never changes after the build; and a test can hold all nine
//! catalogues to the same key set, which is the one check that actually prevents a missing sentence.
//!
//! # English is the one that is tested
//!
//! The eight translations are machine-drafted and have not been read by a native speaker, so every disclosure
//! shown in one of them ends with a sentence saying exactly that — see [`Language::caveat`]. A translation that
//! quietly presents itself as authoritative is worse than no translation, because the whole point of a
//! disclosure is that the reader can rely on it.
//!
//! # No plural engine
//!
//! Where English switches between "one field travels" and "three fields travel", there are two keys and each
//! language fills in both. Nine languages' plural rules are a dependency, and a sentence that reads slightly
//! stiff is a smaller problem than one that is wrong. For the same reason the number is spelled out in words
//! only in English, where the house style asks for it, and written as a digit everywhere else.

mod catalogue;

/// A language Flowlight speaks.
///
/// The eight beside English are the ones the macOS build ships, so that the two builds say the same things to
/// the same people.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Language {
    /// The one the program is written and tested in.
    #[default]
    English,
    /// Deutsch.
    German,
    /// Español.
    Spanish,
    /// Français.
    French,
    /// Italiano.
    Italian,
    /// 日本語.
    Japanese,
    /// 한국어.
    Korean,
    /// Português.
    Portuguese,
    /// 简体中文.
    Chinese,
}

/// Every language, in the order a list of them is offered.
pub const EVERY_LANGUAGE: &[Language] = &[
    Language::English,
    Language::German,
    Language::Spanish,
    Language::French,
    Language::Italian,
    Language::Japanese,
    Language::Korean,
    Language::Portuguese,
    Language::Chinese,
];

impl Language {
    /// The tag this is written down as.
    pub fn tag(self) -> &'static str {
        match self {
            Self::English => "en",
            Self::German => "de",
            Self::Spanish => "es",
            Self::French => "fr",
            Self::Italian => "it",
            Self::Japanese => "ja",
            Self::Korean => "ko",
            Self::Portuguese => "pt",
            Self::Chinese => "zh-Hans",
        }
    }

    /// What the language calls itself.
    ///
    /// Its own name rather than its English one: somebody looking for their language in a list is looking for
    /// the word they would use for it.
    pub fn endonym(self) -> &'static str {
        match self {
            Self::English => "English",
            Self::German => "Deutsch",
            Self::Spanish => "Español",
            Self::French => "Français",
            Self::Italian => "Italiano",
            Self::Japanese => "日本語",
            Self::Korean => "한국어",
            Self::Portuguese => "Português",
            Self::Chinese => "简体中文",
        }
    }

    /// Reads a tag, a locale, or the contents of `LANG`.
    ///
    /// Tolerant about the shape — `de`, `de_DE`, `de-DE.UTF-8@euro` are the same answer — and deliberately
    /// intolerant about one thing: traditional Chinese is not simplified Chinese, so `zh-TW` is not answered
    /// with the `zh-Hans` catalogue. Serving a reader text in a script they did not ask for, while claiming to
    /// have their language, is the failure a language list exists to prevent.
    pub fn parse(text: &str) -> Option<Self> {
        let cleaned = text.trim().to_lowercase().replace('_', "-");
        let cleaned = cleaned
            .split(['.', '@'])
            .next()
            .unwrap_or_default()
            .to_owned();
        let mut parts = cleaned.split('-');
        let primary = parts.next().unwrap_or_default();
        let rest: Vec<&str> = parts.collect();
        match primary {
            "en" => Some(Self::English),
            "de" => Some(Self::German),
            "es" => Some(Self::Spanish),
            "fr" => Some(Self::French),
            "it" => Some(Self::Italian),
            "ja" => Some(Self::Japanese),
            "ko" => Some(Self::Korean),
            "pt" => Some(Self::Portuguese),
            "zh" => {
                if rest
                    .iter()
                    .any(|part| matches!(*part, "hant" | "tw" | "hk" | "mo"))
                {
                    None
                } else {
                    Some(Self::Chinese)
                }
            }
            _ => None,
        }
    }

    /// The language the environment asks for, if it asks for one this program has.
    ///
    /// `FLOWLIGHT_LANGUAGE` first, because a setting for this program should win over the machine's; then the
    /// locale variables in the order the C library reads them. `C` and `POSIX` are not a request for English so
    /// much as the absence of a request, and the answer is the same either way.
    pub fn from_environment(read: impl Fn(&str) -> Option<String>) -> Option<Self> {
        for name in ["FLOWLIGHT_LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"] {
            let Some(value) = read(name) else { continue };
            if value.trim().is_empty() {
                continue;
            }
            if let Some(language) = Self::parse(&value) {
                return Some(language);
            }
        }
        None
    }

    /// The language this process's environment asks for, or English.
    pub fn detected() -> Self {
        Self::from_environment(|name| std::env::var(name).ok()).unwrap_or_default()
    }

    /// Whether this is a translation rather than the original.
    pub fn is_translated(self) -> bool {
        self != Self::English
    }

    /// The sentence a translated disclosure ends with, saying which wording is the one that binds.
    ///
    /// `None` in English, where there is nothing to say: the English *is* the tested wording.
    pub fn caveat(self) -> Option<&'static str> {
        if self.is_translated() {
            Some(self.say("text.translated"))
        } else {
            None
        }
    }

    /// The catalogue for this language.
    fn phrases(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::English => catalogue::en::PHRASES,
            Self::German => catalogue::de::PHRASES,
            Self::Spanish => catalogue::es::PHRASES,
            Self::French => catalogue::fr::PHRASES,
            Self::Italian => catalogue::it::PHRASES,
            Self::Japanese => catalogue::ja::PHRASES,
            Self::Korean => catalogue::ko::PHRASES,
            Self::Portuguese => catalogue::pt::PHRASES,
            Self::Chinese => catalogue::zh::PHRASES,
        }
    }

    /// One phrase.
    ///
    /// Falls back to English and then to the key itself. A test asserts every catalogue holds every key, so the
    /// fallback is for the change that adds a key and forgets a language rather than a promise being made here:
    /// an English sentence in a German paragraph is ugly, and a missing sentence in a disclosure is a lie.
    ///
    /// A linear scan, over sixty-odd entries, on a path that renders a paragraph a person is about to read.
    ///
    /// The key is `&'static str` rather than `&str` because every one is a literal written in this repository,
    /// and saying so is what lets the last fallback be the key itself rather than an empty sentence.
    pub fn say(self, key: &'static str) -> &'static str {
        find(self.phrases(), key)
            .or_else(|| find(catalogue::en::PHRASES, key))
            .unwrap_or(key)
    }

    /// One phrase with its placeholders filled in.
    ///
    /// A placeholder nothing was given for is left as it is, so that it shows up in a test or on a screen
    /// rather than becoming an empty space in a sentence about what leaves the machine.
    pub fn fill(self, key: &'static str, values: &[(&str, &str)]) -> String {
        let mut text = self.say(key).to_owned();
        for (name, value) in values {
            text = text.replace(&format!("{{{name}}}"), value);
        }
        text
    }

    /// A small number as a sentence would carry it.
    ///
    /// Spelled out in English, where a sentence that starts with a digit reads like a log line, and written as
    /// a digit in the other eight — number words are a per-language table of their own, and a digit is correct
    /// in all of them.
    pub fn counted(self, many: usize) -> String {
        if self != Self::English {
            return many.to_string();
        }
        match many {
            0 => "No",
            1 => "One",
            2 => "Two",
            3 => "Three",
            4 => "Four",
            5 => "Five",
            6 => "Six",
            7 => "Seven",
            8 => "Eight",
            9 => "Nine",
            10 => "Ten",
            11 => "Eleven",
            12 => "Twelve",
            13 => "Thirteen",
            14 => "Fourteen",
            _ => "Several",
        }
        .to_owned()
    }

    /// A count of days, with the word for them.
    pub fn days(self, many: u32) -> String {
        let key = if many == 1 { "days.one" } else { "days.many" };
        self.fill(key, &[("count", &many.to_string())])
    }
}

/// A phrase in a catalogue, if it is there.
fn find(phrases: &'static [(&'static str, &'static str)], key: &str) -> Option<&'static str> {
    phrases
        .iter()
        .find(|(candidate, _)| *candidate == key)
        .map(|(_, text)| *text)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The check that matters, and the reason the catalogue is code rather than a file: a language that is
    /// missing a sentence is a build that fails rather than a disclosure with a hole in it.
    #[test]
    fn every_language_says_everything_english_says() {
        for language in EVERY_LANGUAGE {
            for (key, _) in catalogue::en::PHRASES {
                assert!(
                    find(language.phrases(), key).is_some(),
                    "{} is missing {key}",
                    language.tag()
                );
            }
        }
    }

    /// And nothing extra, which is how a key renamed in English leaves eight dead entries behind.
    #[test]
    fn no_language_says_anything_english_does_not() {
        for language in EVERY_LANGUAGE {
            for (key, _) in language.phrases() {
                assert!(
                    find(catalogue::en::PHRASES, key).is_some(),
                    "{} has {key}, which English does not",
                    language.tag()
                );
            }
        }
    }

    /// A placeholder is the part of a sentence that carries the fact. A translation that spells one differently
    /// does not fail to translate a word — it silently drops the destination, or the endpoint, out of a
    /// disclosure, and reads perfectly well without it.
    #[test]
    fn the_placeholders_survive_translation() {
        for language in EVERY_LANGUAGE {
            for (key, english) in catalogue::en::PHRASES {
                let translated = language.say(key);
                for name in placeholders(english) {
                    assert!(
                        translated.contains(&name),
                        "{} is missing {name} in {key}",
                        language.tag()
                    );
                }
                for name in placeholders(translated) {
                    assert!(
                        english.contains(&name),
                        "{} has {name} in {key}, which English does not",
                        language.tag()
                    );
                }
            }
        }
    }

    /// Nothing blank, in any of them.
    #[test]
    fn no_catalogue_holds_an_empty_sentence() {
        for language in EVERY_LANGUAGE {
            for (key, text) in language.phrases() {
                assert!(
                    !text.trim().is_empty(),
                    "{} has {key} empty",
                    language.tag()
                );
            }
        }
    }

    /// Every key exactly once, or `say` returns whichever came first and the other is dead text.
    #[test]
    fn no_catalogue_says_the_same_thing_twice() {
        for language in EVERY_LANGUAGE {
            let mut keys: Vec<&str> = language.phrases().iter().map(|(key, _)| *key).collect();
            let before = keys.len();
            keys.sort_unstable();
            keys.dedup();
            assert_eq!(before, keys.len(), "{} repeats a key", language.tag());
        }
    }

    /// Every placeholder in a piece of text, as `{name}` including the braces.
    fn placeholders(text: &str) -> Vec<String> {
        let mut found = Vec::new();
        let mut rest = text;
        while let Some(start) = rest.find('{') {
            let Some(tail) = rest.get(start + 1..) else {
                break;
            };
            let Some(end) = tail.find('}') else { break };
            if let Some(name) = tail.get(..end) {
                found.push(format!("{{{name}}}"));
            }
            rest = tail.get(end + 1..).unwrap_or_default();
        }
        found
    }

    #[test]
    fn a_locale_is_read_however_it_is_written() {
        assert_eq!(Language::parse("de"), Some(Language::German));
        assert_eq!(Language::parse("de_DE.UTF-8"), Some(Language::German));
        assert_eq!(Language::parse("pt-BR"), Some(Language::Portuguese));
        assert_eq!(Language::parse("fr_FR.UTF-8@euro"), Some(Language::French));
        assert_eq!(Language::parse("zh_CN.UTF-8"), Some(Language::Chinese));
        assert_eq!(Language::parse("C"), None);
        assert_eq!(Language::parse("POSIX"), None);
        assert_eq!(Language::parse("tlh"), None);
    }

    /// Simplified text is not what somebody reading traditional Chinese asked for, and answering `zh-TW` with
    /// it would be claiming a language this does not have.
    #[test]
    fn traditional_chinese_is_not_answered_with_simplified() {
        assert_eq!(Language::parse("zh-Hant"), None);
        assert_eq!(Language::parse("zh_TW.UTF-8"), None);
        assert_eq!(Language::parse("zh-HK"), None);
        assert_eq!(Language::parse("zh-Hans"), Some(Language::Chinese));
        assert_eq!(Language::parse("zh"), Some(Language::Chinese));
    }

    /// This program's own setting beats the machine's locale, and an empty variable is not an answer.
    #[test]
    fn the_programs_own_setting_wins() {
        let environment = |name: &str| match name {
            "FLOWLIGHT_LANGUAGE" => Some("ja".to_owned()),
            "LANG" => Some("de_DE.UTF-8".to_owned()),
            _ => None,
        };
        assert_eq!(
            Language::from_environment(environment),
            Some(Language::Japanese)
        );

        let blank = |name: &str| match name {
            "FLOWLIGHT_LANGUAGE" => Some("   ".to_owned()),
            "LC_ALL" => Some("C".to_owned()),
            "LANG" => Some("ko_KR.UTF-8".to_owned()),
            _ => None,
        };
        assert_eq!(Language::from_environment(blank), Some(Language::Korean));
        assert_eq!(Language::from_environment(|_| None), None);
    }

    #[test]
    fn a_placeholder_is_filled_and_an_unknown_one_is_left_visible() {
        let filled = Language::English.fill(
            "export.destination.otlp",
            &[("destination", "http://localhost:4318")],
        );
        assert!(filled.contains("http://localhost:4318"), "{filled}");
        assert!(!filled.contains('{'), "{filled}");
        assert!(
            Language::English
                .fill("export.destination.otlp", &[])
                .contains("{destination}")
        );
    }

    /// The caveat is not optional decoration: it is the sentence that says which wording binds.
    #[test]
    fn a_translated_disclosure_says_which_wording_binds() {
        assert_eq!(Language::English.caveat(), None);
        for language in EVERY_LANGUAGE.iter().filter(|it| it.is_translated()) {
            let caveat = language.caveat().unwrap_or_default();
            assert!(caveat.len() > 20, "{} has no caveat", language.tag());
            assert_ne!(
                caveat,
                Language::English.say("text.translated"),
                "{} has the English caveat",
                language.tag()
            );
        }
    }

    /// English spells a small number out; the others use a digit, which is correct in all of them.
    #[test]
    fn a_number_is_a_word_in_english_and_a_digit_elsewhere() {
        assert_eq!(Language::English.counted(3), "Three");
        assert_eq!(Language::German.counted(3), "3");
        assert_eq!(Language::English.counted(40), "Several");
        assert_eq!(Language::Japanese.counted(40), "40");
    }

    #[test]
    fn a_day_and_several_days_are_different_sentences() {
        assert_eq!(Language::English.days(1), "1 day");
        assert_eq!(Language::English.days(7), "7 days");
        for language in EVERY_LANGUAGE {
            assert!(language.days(1).contains('1'));
            assert!(language.days(7).contains('7'));
        }
    }

    /// A tag written out and read back is the same language, which is what the stored setting relies on.
    #[test]
    fn a_tag_round_trips() {
        for language in EVERY_LANGUAGE {
            assert_eq!(Language::parse(language.tag()), Some(*language));
        }
    }
}
