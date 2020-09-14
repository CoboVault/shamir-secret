/*
 *  BIP39 library, a Java implementation of BIP39
 *  Copyright (C) 2017-2019 Alan Evans, NovaCrypto
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *  Original source: https://github.com/NovaCrypto/BIP39
 *  You can contact the authors via github issues.
 */
package iton.slip.secret.words;


/**
 * Source: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
 */
public enum Words {
    INSTANCE;

    public String getWord(final int index) {
        return words[index];
    }

    public char getSpace() {
        return ' ';
    }

    public String[] getWords() {
        return words;
    }
    public final static String[] words = new String[]{
            "academic", "acid", "acne", "acquire", "acrobat", "activity", "actress", "adapt", "adequate",
            "adjust", "admit", "adorn", "adult", "advance", "advocate", "afraid", "again", "agency",
            "agree", "aide", "aircraft", "airline", "airport", "ajar", "alarm", "album", "alcohol",
            "alien", "alive", "alpha", "already", "alto", "aluminum", "always", "amazing", "ambition",
            "amount", "amuse", "analysis", "anatomy", "ancestor", "ancient", "angel", "angry", "animal",
            "answer", "antenna", "anxiety", "apart", "aquatic", "arcade", "arena", "argue", "armed",
            "artist", "artwork", "aspect", "auction", "august", "aunt", "average", "aviation", "avoid",
            "award", "away", "axis", "axle", "beam", "beard", "beaver", "become", "bedroom", "behavior",
            "being", "believe", "belong", "benefit", "best", "beyond", "bike", "biology", "birthday",
            "bishop", "black", "blanket", "blessing", "blimp", "blind", "blue", "body", "bolt", "boring",
            "born", "both", "boundary", "bracelet", "branch", "brave", "breathe", "briefing", "broken",
            "brother", "browser", "bucket", "budget", "building", "bulb", "bulge", "bumpy", "bundle",
            "burden", "burning", "busy", "buyer", "cage", "calcium", "camera", "campus", "canyon",
            "capacity", "capital", "capture", "carbon", "cards", "careful", "cargo", "carpet", "carve",
            "category", "cause", "ceiling", "center", "ceramic", "champion", "change", "charity", "check",
            "chemical", "chest", "chew", "chubby", "cinema", "civil", "class", "clay", "cleanup", "client",
            "climate", "clinic", "clock", "clogs", "closet", "clothes", "club", "cluster", "coal",
            "coastal", "coding", "column", "company", "corner", "costume", "counter", "course", "cover",
            "cowboy", "cradle", "craft", "crazy", "credit", "cricket", "criminal", "crisis", "critical",
            "crowd", "crucial", "crunch", "crush", "crystal", "cubic", "cultural", "curious", "curly",
            "custody", "cylinder", "daisy", "damage", "dance", "darkness", "database", "daughter",
            "deadline", "deal", "debris", "debut", "decent", "decision", "declare", "decorate", "decrease",
            "deliver", "demand", "density", "deny", "depart", "depend", "depict", "deploy", "describe",
            "desert", "desire", "desktop", "destroy", "detailed", "detect", "device", "devote", "diagnose",
            "dictate", "diet", "dilemma", "diminish", "dining", "diploma", "disaster", "discuss",
            "disease", "dish", "dismiss", "display", "distance", "dive", "divorce", "document", "domain",
            "domestic", "dominant", "dough", "downtown", "dragon", "dramatic", "dream", "dress", "drift",
            "drink", "drove", "drug", "dryer", "duckling", "duke", "duration", "dwarf", "dynamic", "early",
            "earth", "easel", "easy", "echo", "eclipse", "ecology", "edge", "editor", "educate", "either",
            "elbow", "elder", "election", "elegant", "element", "elephant", "elevator", "elite", "else",
            "email", "emerald", "emission", "emperor", "emphasis", "employer", "empty", "ending",
            "endless", "endorse", "enemy", "energy", "enforce", "engage", "enjoy", "enlarge", "entrance",
            "envelope", "envy", "epidemic", "episode", "equation", "equip", "eraser", "erode", "escape",
            "estate", "estimate", "evaluate", "evening", "evidence", "evil", "evoke", "exact", "example",
            "exceed", "exchange", "exclude", "excuse", "execute", "exercise", "exhaust", "exotic",
            "expand", "expect", "explain", "express", "extend", "extra", "eyebrow", "facility", "fact",
            "failure", "faint", "fake", "false", "family", "famous", "fancy", "fangs", "fantasy", "fatal",
            "fatigue", "favorite", "fawn", "fiber", "fiction", "filter", "finance", "findings", "finger",
            "firefly", "firm", "fiscal", "fishing", "fitness", "flame", "flash", "flavor", "flea",
            "flexible", "flip", "float", "floral", "fluff", "focus", "forbid", "force", "forecast",
            "forget", "formal", "fortune", "forward", "founder", "fraction", "fragment", "frequent",
            "freshman", "friar", "fridge", "friendly", "frost", "froth", "frozen", "fumes", "funding",
            "furl", "fused", "galaxy", "game", "garbage", "garden", "garlic", "gasoline", "gather",
            "general", "genius", "genre", "genuine", "geology", "gesture", "glad", "glance", "glasses",
            "glen", "glimpse", "goat", "golden", "graduate", "grant", "grasp", "gravity", "gray",
            "greatest", "grief", "grill", "grin", "grocery", "gross", "group", "grownup", "grumpy",
            "guard", "guest", "guilt", "guitar", "gums", "hairy", "hamster", "hand", "hanger", "harvest",
            "have", "havoc", "hawk", "hazard", "headset", "health", "hearing", "heat", "helpful", "herald",
            "herd", "hesitate", "hobo", "holiday", "holy", "home", "hormone", "hospital", "hour", "huge",
            "human", "humidity", "hunting", "husband", "hush", "husky", "hybrid", "idea", "identify",
            "idle", "image", "impact", "imply", "improve", "impulse", "include", "income", "increase",
            "index", "indicate", "industry", "infant", "inform", "inherit", "injury", "inmate", "insect",
            "inside", "install", "intend", "intimate", "invasion", "involve", "iris", "island", "isolate",
            "item", "ivory", "jacket", "jerky", "jewelry", "join", "judicial", "juice", "jump", "junction",
            "junior", "junk", "jury", "justice", "kernel", "keyboard", "kidney", "kind", "kitchen",
            "knife", "knit", "laden", "ladle", "ladybug", "lair", "lamp", "language", "large", "laser",
            "laundry", "lawsuit", "leader", "leaf", "learn", "leaves", "lecture", "legal", "legend",
            "legs", "lend", "length", "level", "liberty", "library", "license", "lift", "likely", "lilac",
            "lily", "lips", "liquid", "listen", "literary", "living", "lizard", "loan", "lobe", "location",
            "losing", "loud", "loyalty", "luck", "lunar", "lunch", "lungs", "luxury", "lying", "lyrics",
            "machine", "magazine", "maiden", "mailman", "main", "makeup", "making", "mama", "manager",
            "mandate", "mansion", "manual", "marathon", "march", "market", "marvel", "mason", "material",
            "math", "maximum", "mayor", "meaning", "medal", "medical", "member", "memory", "mental",
            "merchant", "merit", "method", "metric", "midst", "mild", "military", "mineral", "minister",
            "miracle", "mixed", "mixture", "mobile", "modern", "modify", "moisture", "moment", "morning",
            "mortgage", "mother", "mountain", "mouse", "move", "much", "mule", "multiple", "muscle",
            "museum", "music", "mustang", "nail", "national", "necklace", "negative", "nervous", "network",
            "news", "nuclear", "numb", "numerous", "nylon", "oasis", "obesity", "object", "observe",
            "obtain", "ocean", "often", "olympic", "omit", "oral", "orange", "orbit", "order", "ordinary",
            "organize", "ounce", "oven", "overall", "owner", "paces", "pacific", "package", "paid",
            "painting", "pajamas", "pancake", "pants", "papa", "paper", "parcel", "parking", "party",
            "patent", "patrol", "payment", "payroll", "peaceful", "peanut", "peasant", "pecan", "penalty",
            "pencil", "percent", "perfect", "permit", "petition", "phantom", "pharmacy", "photo", "phrase",
            "physics", "pickup", "picture", "piece", "pile", "pink", "pipeline", "pistol", "pitch",
            "plains", "plan", "plastic", "platform", "playoff", "pleasure", "plot", "plunge", "practice",
            "prayer", "preach", "predator", "pregnant", "premium", "prepare", "presence", "prevent",
            "priest", "primary", "priority", "prisoner", "privacy", "prize", "problem", "process",
            "profile", "program", "promise", "prospect", "provide", "prune", "public", "pulse", "pumps",
            "punish", "puny", "pupal", "purchase", "purple", "python", "quantity", "quarter", "quick",
            "quiet", "race", "racism", "radar", "railroad", "rainbow", "raisin", "random", "ranked",
            "rapids", "raspy", "reaction", "realize", "rebound", "rebuild", "recall", "receiver",
            "recover", "regret", "regular", "reject", "relate", "remember", "remind", "remove", "render",
            "repair", "repeat", "replace", "require", "rescue", "research", "resident", "response",
            "result", "retailer", "retreat", "reunion", "revenue", "review", "reward", "rhyme", "rhythm",
            "rich", "rival", "river", "robin", "rocky", "romantic", "romp", "roster", "round", "royal",
            "ruin", "ruler", "rumor", "sack", "safari", "salary", "salon", "salt", "satisfy", "satoshi",
            "saver", "says", "scandal", "scared", "scatter", "scene", "scholar", "science", "scout",
            "scramble", "screw", "script", "scroll", "seafood", "season", "secret", "security", "segment",
            "senior", "shadow", "shaft", "shame", "shaped", "sharp", "shelter", "sheriff", "short",
            "should", "shrimp", "sidewalk", "silent", "silver", "similar", "simple", "single", "sister",
            "skin", "skunk", "slap", "slavery", "sled", "slice", "slim", "slow", "slush", "smart", "smear",
            "smell", "smirk", "smith", "smoking", "smug", "snake", "snapshot", "sniff", "society",
            "software", "soldier", "solution", "soul", "source", "space", "spark", "speak", "species",
            "spelling", "spend", "spew", "spider", "spill", "spine", "spirit", "spit", "spray", "sprinkle",
            "square", "squeeze", "stadium", "staff", "standard", "starting", "station", "stay", "steady",
            "step", "stick", "stilt", "story", "strategy", "strike", "style", "subject", "submit", "sugar",
            "suitable", "sunlight", "superior", "surface", "surprise", "survive", "sweater", "swimming",
            "swing", "switch", "symbolic", "sympathy", "syndrome", "system", "tackle", "tactics",
            "tadpole", "talent", "task", "taste", "taught", "taxi", "teacher", "teammate", "teaspoon",
            "temple", "tenant", "tendency", "tension", "terminal", "testify", "texture", "thank", "that",
            "theater", "theory", "therapy", "thorn", "threaten", "thumb", "thunder", "ticket", "tidy",
            "timber", "timely", "ting", "tofu", "together", "tolerate", "total", "toxic", "tracks",
            "traffic", "training", "transfer", "trash", "traveler", "treat", "trend", "trial", "tricycle",
            "trip", "triumph", "trouble", "true", "trust", "twice", "twin", "type", "typical", "ugly",
            "ultimate", "umbrella", "uncover", "undergo", "unfair", "unfold", "unhappy", "union",
            "universe", "unkind", "unknown", "unusual", "unwrap", "upgrade", "upstairs", "username",
            "usher", "usual", "valid", "valuable", "vampire", "vanish", "various", "vegan", "velvet",
            "venture", "verdict", "verify", "very", "veteran", "vexed", "victim", "video", "view",
            "vintage", "violence", "viral", "visitor", "visual", "vitamins", "vocal", "voice", "volume",
            "voter", "voting", "walnut", "warmth", "warn", "watch", "wavy", "wealthy", "weapon", "webcam",
            "welcome", "welfare", "western", "width", "wildlife", "window", "wine", "wireless", "wisdom",
            "withdraw", "wits", "wolf", "woman", "work", "worthy", "wrap", "wrist", "writing", "wrote",
            "year", "yelp", "yield", "yoga", "zero"
    };
}
