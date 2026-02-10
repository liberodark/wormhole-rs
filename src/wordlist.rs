use rand::RngExt;

const WORD_PAIRS: [(&str, &str); 256] = [
    ("aardvark", "adroitness"),
    ("absurd", "adviser"),
    ("accrue", "aftermath"),
    ("acme", "aggregate"),
    ("adrift", "alkali"),
    ("adult", "almighty"),
    ("afflict", "amulet"),
    ("ahead", "amusement"),
    ("aimless", "antenna"),
    ("algol", "applicant"),
    ("allow", "apollo"),
    ("alone", "armistice"),
    ("ammo", "article"),
    ("ancient", "asteroid"),
    ("apple", "atlantic"),
    ("artist", "atmosphere"),
    ("assume", "autopsy"),
    ("athens", "babylon"),
    ("atlas", "backwater"),
    ("aztec", "barbecue"),
    ("baboon", "belowground"),
    ("backfield", "bifocals"),
    ("backward", "bodyguard"),
    ("banjo", "bookseller"),
    ("beaming", "borderline"),
    ("bedlamp", "bottomless"),
    ("beehive", "bradbury"),
    ("beeswax", "bravado"),
    ("befriend", "brazilian"),
    ("belfast", "breakaway"),
    ("berserk", "burlington"),
    ("billiard", "businessman"),
    ("bison", "butterfat"),
    ("blackjack", "camelot"),
    ("blockade", "candidate"),
    ("blowtorch", "cannonball"),
    ("bluebird", "capricorn"),
    ("bombast", "caravan"),
    ("bookshelf", "caretaker"),
    ("brackish", "celebrate"),
    ("breadline", "cellulose"),
    ("breakup", "certify"),
    ("brickyard", "chambermaid"),
    ("briefcase", "cherokee"),
    ("burbank", "chicago"),
    ("button", "clergyman"),
    ("buzzard", "coherence"),
    ("cement", "combustion"),
    ("chairlift", "commando"),
    ("chatter", "company"),
    ("checkup", "component"),
    ("chisel", "concurrent"),
    ("choking", "confidence"),
    ("chopper", "conformist"),
    ("christmas", "congregate"),
    ("clamshell", "consensus"),
    ("classic", "consulting"),
    ("classroom", "corporate"),
    ("cleanup", "corrosion"),
    ("clockwork", "councilman"),
    ("cobra", "crossover"),
    ("commence", "crucifix"),
    ("concert", "cumbersome"),
    ("cowbell", "customer"),
    ("crackdown", "dakota"),
    ("cranky", "decadence"),
    ("crowfoot", "december"),
    ("crucial", "decimal"),
    ("crumpled", "designing"),
    ("crusade", "detector"),
    ("cubic", "detergent"),
    ("dashboard", "determine"),
    ("deadbolt", "dictator"),
    ("deckhand", "dinosaur"),
    ("dogsled", "direction"),
    ("dragnet", "disable"),
    ("drainage", "disbelief"),
    ("dreadful", "disruptive"),
    ("drifter", "distortion"),
    ("dropper", "document"),
    ("drumbeat", "embezzle"),
    ("drunken", "enchanting"),
    ("dupont", "enrollment"),
    ("dwelling", "enterprise"),
    ("eating", "equation"),
    ("edict", "equipment"),
    ("egghead", "escapade"),
    ("eightball", "eskimo"),
    ("endorse", "everyday"),
    ("endow", "examine"),
    ("enlist", "existence"),
    ("erase", "exodus"),
    ("escape", "fascinate"),
    ("exceed", "filament"),
    ("eyeglass", "finicky"),
    ("eyetooth", "forever"),
    ("facial", "fortitude"),
    ("fallout", "frequency"),
    ("flagpole", "gadgetry"),
    ("flatfoot", "galveston"),
    ("flytrap", "getaway"),
    ("fracture", "glossary"),
    ("framework", "gossamer"),
    ("freedom", "graduate"),
    ("frighten", "gravity"),
    ("gazelle", "guitarist"),
    ("geiger", "hamburger"),
    ("glitter", "hamilton"),
    ("glucose", "handiwork"),
    ("goggles", "hazardous"),
    ("goldfish", "headwaters"),
    ("gremlin", "hemisphere"),
    ("guidance", "hesitate"),
    ("hamlet", "hideaway"),
    ("highchair", "holiness"),
    ("hockey", "hurricane"),
    ("indoors", "hydraulic"),
    ("indulge", "impartial"),
    ("inverse", "impetus"),
    ("involve", "inception"),
    ("island", "indigo"),
    ("jawbone", "inertia"),
    ("keyboard", "infancy"),
    ("kickoff", "inferno"),
    ("kiwi", "informant"),
    ("klaxon", "insincere"),
    ("locale", "insurgent"),
    ("lockup", "integrate"),
    ("merit", "intention"),
    ("minnow", "inventive"),
    ("miser", "istanbul"),
    ("mohawk", "jamaica"),
    ("mural", "jupiter"),
    ("music", "leprosy"),
    ("necklace", "letterhead"),
    ("neptune", "liberty"),
    ("newborn", "maritime"),
    ("nightbird", "matchmaker"),
    ("oakland", "maverick"),
    ("obtuse", "medusa"),
    ("offload", "megaton"),
    ("optic", "microscope"),
    ("orca", "microwave"),
    ("payday", "midsummer"),
    ("peachy", "millionaire"),
    ("pheasant", "miracle"),
    ("physique", "misnomer"),
    ("playhouse", "molasses"),
    ("pluto", "molecule"),
    ("preclude", "montana"),
    ("prefer", "monument"),
    ("preshrunk", "mosquito"),
    ("printer", "narrative"),
    ("prowler", "nebula"),
    ("pupil", "newsletter"),
    ("puppy", "norwegian"),
    ("python", "october"),
    ("quadrant", "ohio"),
    ("quiver", "onlooker"),
    ("quota", "opulent"),
    ("ragtime", "orlando"),
    ("ratchet", "outfielder"),
    ("rebirth", "pacific"),
    ("reform", "pandemic"),
    ("regain", "pandora"),
    ("reindeer", "paperweight"),
    ("rematch", "paragon"),
    ("repay", "paragraph"),
    ("retouch", "paramount"),
    ("revenge", "passenger"),
    ("reward", "pedigree"),
    ("rhythm", "pegasus"),
    ("ribcage", "penetrate"),
    ("ringbolt", "perceptive"),
    ("robust", "performance"),
    ("rocker", "pharmacy"),
    ("ruffled", "phonetic"),
    ("sailboat", "photograph"),
    ("sawdust", "pioneer"),
    ("scallion", "pocketful"),
    ("scenic", "politeness"),
    ("scorecard", "positive"),
    ("scotland", "potato"),
    ("seabird", "processor"),
    ("select", "provincial"),
    ("sentence", "proximate"),
    ("shadow", "puberty"),
    ("shamrock", "publisher"),
    ("showgirl", "pyramid"),
    ("skullcap", "quantity"),
    ("skydive", "racketeer"),
    ("slingshot", "rebellion"),
    ("slowdown", "recipe"),
    ("snapline", "recover"),
    ("snapshot", "repellent"),
    ("snowcap", "replica"),
    ("snowslide", "reproduce"),
    ("solo", "resistor"),
    ("southward", "responsive"),
    ("soybean", "retraction"),
    ("spaniel", "retrieval"),
    ("spearhead", "retrospect"),
    ("spellbind", "revenue"),
    ("spheroid", "revival"),
    ("spigot", "revolver"),
    ("spindle", "sandalwood"),
    ("spyglass", "sardonic"),
    ("stagehand", "saturday"),
    ("stagnate", "savagery"),
    ("stairway", "scavenger"),
    ("standard", "sensation"),
    ("stapler", "sociable"),
    ("steamship", "souvenir"),
    ("sterling", "specialist"),
    ("stockman", "speculate"),
    ("stopwatch", "stethoscope"),
    ("stormy", "stupendous"),
    ("sugar", "supportive"),
    ("surmount", "surrender"),
    ("suspense", "suspicious"),
    ("sweatband", "sympathy"),
    ("swelter", "tambourine"),
    ("tactics", "telephone"),
    ("talon", "therapist"),
    ("tapeworm", "tobacco"),
    ("tempest", "tolerance"),
    ("tiger", "tomorrow"),
    ("tissue", "torpedo"),
    ("tonic", "tradition"),
    ("topmost", "travesty"),
    ("tracker", "trombonist"),
    ("transit", "truncated"),
    ("trauma", "typewriter"),
    ("treadmill", "ultimate"),
    ("trojan", "undaunted"),
    ("trouble", "underfoot"),
    ("tumor", "unicorn"),
    ("tunnel", "unify"),
    ("tycoon", "universe"),
    ("uncut", "unravel"),
    ("unearth", "upcoming"),
    ("unwind", "vacancy"),
    ("uproot", "vagabond"),
    ("upset", "vertigo"),
    ("upshot", "virginia"),
    ("vapor", "visitor"),
    ("village", "vocalist"),
    ("virus", "voyager"),
    ("vulcan", "warranty"),
    ("waffle", "waterloo"),
    ("wallet", "whimsical"),
    ("watchword", "wichita"),
    ("wayside", "wilmington"),
    ("willow", "wyoming"),
    ("woodlark", "yesteryear"),
    ("zulu", "yucatan"),
];

pub fn generate_passphrase(word_count: usize) -> String {
    let mut rng = rand::rng();
    let mut words = Vec::with_capacity(word_count);

    for i in 0..word_count {
        let byte: u8 = rng.random();
        let (even, odd) = WORD_PAIRS[byte as usize];

        if i % 2 == 0 {
            words.push(odd);
        } else {
            words.push(even);
        }
    }

    words.join("-")
}

#[cfg(test)]
pub fn get_word(byte: u8, position: usize) -> &'static str {
    let (even, odd) = WORD_PAIRS[byte as usize];
    if position.is_multiple_of(2) {
        odd
    } else {
        even
    }
}

#[cfg(test)]
pub fn find_completions(partial: &str, position: usize) -> Vec<&'static str> {
    let partial_lower = partial.to_lowercase();
    WORD_PAIRS
        .iter()
        .filter_map(|(even, odd)| {
            let word = if position.is_multiple_of(2) {
                *odd
            } else {
                *even
            };
            if word.starts_with(&partial_lower) {
                Some(word)
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_passphrase_length() {
        let passphrase = generate_passphrase(2);
        let words: Vec<_> = passphrase.split('-').collect();
        assert_eq!(words.len(), 2);

        let passphrase = generate_passphrase(4);
        let words: Vec<_> = passphrase.split('-').collect();
        assert_eq!(words.len(), 4);
    }

    #[test]
    fn test_generate_passphrase_format() {
        let passphrase = generate_passphrase(3);
        assert!(!passphrase.is_empty());
        assert!(!passphrase.starts_with('-'));
        assert!(!passphrase.ends_with('-'));
        assert!(!passphrase.contains("--"));
    }

    #[test]
    fn test_get_word() {
        let word = get_word(0, 0);
        assert_eq!(word, "adroitness");

        let word = get_word(0, 1);
        assert_eq!(word, "aardvark");
    }

    #[test]
    fn test_find_completions() {
        let completions = find_completions("ad", 0);
        assert!(completions.contains(&"adroitness"));

        let completions = find_completions("aard", 1);
        assert!(completions.contains(&"aardvark"));
    }

    #[test]
    fn test_word_pairs_count() {
        assert_eq!(WORD_PAIRS.len(), 256);
    }

    #[test]
    fn test_all_words_lowercase() {
        for (even, odd) in WORD_PAIRS {
            assert_eq!(even, even.to_lowercase());
            assert_eq!(odd, odd.to_lowercase());
        }
    }
}
