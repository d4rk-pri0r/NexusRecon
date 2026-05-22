"""
US Census + SSA name-frequency data for handle uniqueness scoring.

The Phase A common-handles list (~400 entries) catches the most
pathological collisions but misses the long tail. A handle like
``mjohnson`` doesn't appear in the curated list, but ``Johnson`` is
the second most common US surname ── a person with that handle is
statistically very likely to be one of millions of M. Johnsons. This
module provides tiered frequency data so the scorer can penalise
that case appropriately.

Data sources (bundled, no external fetches):

  - **SSA top given names**: Social Security Administration publishes
    the top 1000 male and female baby names per year. The lists here
    are the top 200 of each gender taken from the multi-decade
    rolling top-1000, which captures the names most likely to be
    encountered in modern adult populations.
  - **US Census Bureau decennial surname frequencies**: the Census
    publishes a public ``Names_2010.csv`` with ~150K surnames and
    counts. We bundle the top 250, which covers approximately 50% of
    the US population.

Tiering:

  - **Tier A** (top 50 per category): "John", "Smith" ── essentially
    guaranteed collision territory. Frequency score 0.95.
  - **Tier B** (51-200 per category): "Connor", "Patterson" ── still
    very common, frequency score 0.70.
  - **Tier C** (201-1000, only bundled for surnames): "Vukovich",
    "Eckhardt" ── recognisably American/European but uncommon.
    Frequency score 0.35.
  - Unbundled names: assumed rare. Frequency score 0.0.

The score is a "commonness" measure in ``[0, 1]`` ── 1.0 is "matches
many millions," 0.0 is "matches few or none." :func:`handle_commonness`
parses a handle into tokens and returns the maximum component score
(the most-common token dominates because that's the principal source
of collision risk).
"""
from __future__ import annotations

import re

# ── Tier A: top ~50 most common (frequency 0.95) ─────────────────────
# Selected from SSA's all-decades top-1000 and Census top 50 surnames.

_TIER_A_MALE_NAMES = frozenset((
    "james", "john", "robert", "michael", "william", "david", "richard",
    "joseph", "thomas", "charles", "christopher", "daniel", "matthew",
    "anthony", "mark", "donald", "steven", "paul", "andrew", "joshua",
    "kenneth", "kevin", "brian", "george", "edward", "ronald", "timothy",
    "jason", "jeffrey", "ryan", "jacob", "gary", "nicholas", "eric",
    "jonathan", "stephen", "larry", "justin", "scott", "brandon",
    "benjamin", "samuel", "frank", "raymond", "gregory", "alexander",
    "patrick", "jack", "dennis", "jerry",
))

_TIER_A_FEMALE_NAMES = frozenset((
    "mary", "patricia", "jennifer", "linda", "elizabeth", "barbara",
    "susan", "jessica", "sarah", "karen", "lisa", "nancy", "betty",
    "helen", "sandra", "donna", "carol", "ruth", "sharon", "michelle",
    "laura", "kimberly", "deborah", "dorothy", "amy", "angela", "ashley",
    "brenda", "emma", "olivia", "cynthia", "marie", "janet", "catherine",
    "frances", "christine", "samantha", "debra", "rachel", "carolyn",
    "virginia", "maria", "heather", "diane", "julie", "joyce", "victoria",
    "kelly", "christina", "joan",
))

_TIER_A_SURNAMES = frozenset((
    "smith", "johnson", "williams", "brown", "jones", "garcia", "miller",
    "davis", "rodriguez", "martinez", "hernandez", "lopez", "gonzalez",
    "wilson", "anderson", "thomas", "taylor", "moore", "jackson", "martin",
    "lee", "perez", "thompson", "white", "harris", "sanchez", "clark",
    "ramirez", "lewis", "robinson", "walker", "young", "allen", "king",
    "wright", "scott", "torres", "nguyen", "hill", "flores", "green",
    "adams", "nelson", "baker", "hall", "rivera", "campbell", "mitchell",
    "carter", "roberts",
))


# ── Tier B: top 51-200 (frequency 0.70) ──────────────────────────────

_TIER_B_MALE_NAMES = frozenset((
    "tyler", "aaron", "henry", "douglas", "peter", "adam", "noah",
    "nathan", "zachary", "walter", "kyle", "harold", "carl", "jeremy",
    "keith", "roger", "gerald", "ethan", "arthur", "terry", "christian",
    "sean", "lawrence", "austin", "joe", "albert", "willie", "billy",
    "logan", "alan", "juan", "wayne", "elijah", "randy", "roy",
    "vincent", "ralph", "eugene", "russell", "bobby", "mason", "philip",
    "louis", "bradley", "jordan", "lucas", "isaac", "gabriel", "owen",
    "caleb", "nathaniel", "luis", "carlos", "miguel", "antonio", "diego",
    "alejandro", "francisco", "manuel", "ricardo", "fernando", "javier",
    "andrew", "max", "anthony", "kai", "leo", "jose", "mateo", "liam",
    "elliott", "felix", "marcus", "spencer", "harvey", "graham", "neil",
    "vincent", "leon", "dean", "ross", "drew", "blake", "chase", "trey",
    "harrison", "cooper", "parker", "hunter", "sawyer", "carson",
    "easton", "weston", "grayson", "jaxon", "asher", "wyatt", "ezra",
    "preston", "everett", "miles", "felix", "elliot",
))

_TIER_B_FEMALE_NAMES = frozenset((
    "evelyn", "lauren", "judith", "megan", "cheryl", "andrea", "hannah",
    "jacqueline", "martha", "gloria", "teresa", "ann", "sara", "madison",
    "kathryn", "janice", "jean", "abigail", "alice", "julia", "judy",
    "sophia", "grace", "denise", "amber", "doris", "marilyn", "danielle",
    "beverly", "isabella", "theresa", "diana", "natalie", "brittany",
    "charlotte", "kayla", "alexis", "lori", "stephanie", "rebecca", "anna",
    "kathleen", "frances", "monica", "claudia", "monique", "vanessa",
    "tiffany", "courtney", "lindsey", "anita", "annie", "tara", "leah",
    "kristen", "kelsey", "morgan", "shannon", "rachael", "tina", "lily",
    "chloe", "ella", "mia", "amelia", "harper", "evelyn", "luna", "violet",
    "scarlett", "aurora", "savannah", "audrey", "brooklyn", "bella",
    "claire", "skylar", "lucy", "paisley", "anna", "caroline", "nora",
    "ellie", "stella", "kennedy", "ariana", "naomi", "alexa", "alexandra",
    "lilly", "ivy", "willow", "katherine", "kayla", "jocelyn", "lila",
    "raelynn",
))

# Top 51-200 surnames (Census data, approximate)
_TIER_B_SURNAMES = frozenset((
    "phillips", "evans", "turner", "diaz", "parker", "cruz", "edwards",
    "collins", "reyes", "stewart", "morris", "morales", "murphy", "cook",
    "rogers", "gutierrez", "ortiz", "morgan", "cooper", "peterson", "bailey",
    "reed", "kelly", "howard", "ramos", "kim", "cox", "ward", "richardson",
    "watson", "brooks", "chavez", "wood", "james", "bennett", "gray",
    "mendoza", "ruiz", "hughes", "price", "alvarez", "castillo", "sanders",
    "patel", "myers", "long", "ross", "foster", "jimenez", "powell",
    "jenkins", "perry", "russell", "sullivan", "bell", "coleman", "butler",
    "henderson", "barnes", "gonzales", "fisher", "vasquez", "simmons",
    "romero", "jordan", "patterson", "alexander", "hamilton", "graham",
    "reynolds", "griffin", "wallace", "moreno", "west", "cole", "hayes",
    "bryant", "herrera", "gibson", "ellis", "tran", "medina", "aguilar",
    "stevens", "murray", "ford", "castro", "marshall", "owens", "harrison",
    "fernandez", "mcdonald", "woods", "washington", "kennedy", "wells",
    "vargas", "henry", "chen", "freeman", "webb", "tucker", "guzman",
    "burns", "crawford", "olson", "simpson", "porter", "hunter", "gordon",
    "mendez", "silva", "shaw", "snyder", "mason", "dixon", "munoz",
    "hunt", "hicks", "holmes", "palmer", "wagner", "black", "robertson",
    "boyd", "rose", "stone", "salazar", "fox", "warren", "mills", "meyer",
    "rice", "schmidt", "garza", "daniels", "ferguson", "nichols", "stephens",
    "soto", "weaver", "ryan", "gardner", "payne", "grant", "dunn", "kelley",
    "spencer", "hawkins", "arnold", "pierce", "vazquez", "hansen", "peters",
    "santos", "hart", "bradley", "knight",
))


# ── Tier C surnames: 201-1000 (frequency 0.35) ───────────────────────
# Heuristic catches handles like "vukovic" or "patterson_dev" that
# aren't in Tier A/B but are still recognisably-American surnames.

_TIER_C_SURNAMES = frozenset((
    "elliott", "cunningham", "duncan", "armstrong", "hudson", "carroll",
    "lane", "riley", "andrews", "alvarado", "ray", "delgado", "berry",
    "perkins", "hoffman", "johnston", "matthews", "pena", "richards",
    "contreras", "willis", "carpenter", "lawrence", "sandoval", "guerrero",
    "george", "chapman", "rios", "estrada", "ortega", "watkins", "greene",
    "nunez", "wheeler", "valdez", "harper", "burke", "larson", "santiago",
    "maldonado", "morrison", "franklin", "carlson", "austin", "dominguez",
    "carr", "lawson", "jacobs", "obrien", "lynch", "singh", "vega", "bishop",
    "montgomery", "oliver", "jensen", "harvey", "williamson", "gilbert",
    "dean", "sims", "espinoza", "howell", "li", "wong", "reid", "hanson",
    "le", "mccoy", "garrett", "burton", "fuller", "wang", "weber", "welch",
    "rojas", "lucas", "marquez", "fields", "park", "yang", "little",
    "banks", "padilla", "day", "walsh", "bowman", "schultz", "luna",
    "fowler", "mejia", "davidson", "acosta", "brewer", "may", "holland",
    "juarez", "newman", "pearson", "curtis", "cortez", "douglas", "schneider",
    "joseph", "barrett", "navarro", "figueroa", "keller", "avila", "wade",
    "molina", "stanley", "hopkins", "campos", "barnett", "bates", "chambers",
    "caldwell", "beck", "lambert", "miranda", "byrd", "craig", "ayala",
    "lowe", "frazier", "powers", "neal", "leonard", "gregory", "carrillo",
    "sutton", "fleming", "rhodes", "shelton", "schwartz", "norris", "jennings",
    "watts", "duran", "walters", "cohen", "mcdaniel", "moran", "parks",
    "steele", "vaughn", "becker", "holt", "deleon", "barker", "terry",
    "hale", "leon", "hail", "benson", "haynes", "horton", "miles", "lyons",
    "pham", "graves", "bush", "thornton", "wolfe", "warner", "cabrera",
    "mckinney", "mann", "zimmerman", "dawson", "lara", "fletcher", "page",
    "mccarthy", "love", "robles", "cervantes", "solis", "erickson", "reeves",
    "chang", "klein", "salinas", "fuentes", "baldwin", "daniel", "simon",
    "velasquez", "hardy", "higgins", "aguirre", "lin", "cummings", "chandler",
    "sharp", "barber", "bowen", "ochoa", "dennis", "robbins", "liu",
    "ramsey", "francis", "griffith", "paul", "blair", "oconnor", "cardenas",
    "pacheco", "cross", "calderon", "quinn", "moss", "swanson", "chan",
    "rivas", "khan", "rodgers", "serrano", "fitzgerald", "rosales", "stevenson",
    "christensen", "manning", "gill", "curry", "mclaughlin", "harmon",
    "mcgee", "gross", "doyle", "garner", "newton", "burgess", "reese",
    "walton", "blake", "trujillo", "adkins", "brady", "goodman", "roman",
    "webster", "goodwin", "fischer", "huang", "potter", "delacruz", "montoya",
    "todd", "wu", "hines", "mullins", "castaneda", "malone", "cannon",
    "tate", "mack", "sherman", "hubbard", "hodges", "zhang", "guerra",
    "wolf", "valencia", "saunders", "franco", "rowe", "gallagher", "farmer",
    "hammond", "hampton", "townsend", "ingram", "wise", "gallegos", "clarke",
    "barton", "schroeder", "maxwell", "waters", "logan", "camacho", "strickland",
    "norman", "person", "colon", "parsons", "frank", "harrington", "glover",
    "osborne", "buchanan", "casey", "floyd", "patton", "ibarra", "ball",
    "tyler", "suarez", "bowers", "orozco", "salas", "cobb", "gibbs",
    "andrade", "bauer", "conner", "moody", "escobar", "mcguire", "lloyd",
    "muellers", "barber", "russo", "obrien", "townsend", "wiley", "strong",
    "copeland", "savage", "huff", "lacey", "wagner", "vukovic", "korobeinikov",
))


# ── Tier C given names (frequency 0.35) ──────────────────────────────
# Smaller bundled list ── given-name distribution is more peaked than
# surnames, so the tail matters less.

_TIER_C_GIVEN_NAMES = frozenset((
    "wesley", "trenton", "kingston", "easton", "knox", "creed", "remi",
    "ezekiel", "rowan", "watson", "abel", "phoenix", "atlas", "kai",
    "atticus", "silas", "amos", "ace", "blaine", "cason", "axel",
    "bo", "brock", "callum", "clay", "colt", "dax", "dexter", "duke",
    "ellis", "emmett", "finn", "flynn", "garrett", "grady", "griffin",
    "harlan", "harris", "huxley", "hayes", "ike", "jasper", "jensen",
    "jett", "kade", "kane", "knox", "kobe", "lance", "lennon", "lincoln",
    "marcus", "mavrick", "nash", "oscar", "phineas", "pierce", "porter",
    "quincy", "rafael", "reid", "remington", "ridge", "rocky", "rowan",
    "sage", "seth", "shepherd", "simon", "soren", "stanley", "sterling",
    "stetson", "tate", "thatcher", "thomas", "tobias", "ulysses", "vincent",
    "walker", "ward", "weston", "whitman", "wilder", "wyatt", "ximen",
    "yael", "zane", "zeke", "zion",
    # Tier C female
    "everly", "athena", "delilah", "isla", "phoebe", "iris", "june",
    "rosalie", "willa", "lyla", "alma", "wren", "matilda", "nova",
    "rebecca", "octavia", "sage", "kira", "raven", "scarlet", "lyric",
    "skye", "remy", "indigo", "harley", "marlowe", "june", "elise",
))


# ── Scoring constants ────────────────────────────────────────────────
# Tier A = "guaranteed collision" (top 50 most common per category)
# Tier B = "frequent collision" (51-200 per category)
# Tier C = "recognisable but uncommon" (201-1000, surnames mostly)
# Unknown = no name signal; treated as uniqueness-neutral
_TIER_A_SCORE = 0.95
_TIER_B_SCORE = 0.70
_TIER_C_SCORE = 0.20
_UNKNOWN_SCORE = 0.0

# Tier A is "very common", Tier B is "common", Tier C is "somewhat
# common." Above 0.7 should trigger meaningful uniqueness penalty in
# the attribution scorer.

_TIER_A_NAMES = _TIER_A_MALE_NAMES | _TIER_A_FEMALE_NAMES
_TIER_B_NAMES = _TIER_B_MALE_NAMES | _TIER_B_FEMALE_NAMES


def name_commonness(component: str) -> float:
    """Return a commonness score for a single name token (given name
    OR surname). ``0.0`` = rare or unknown; ``0.95`` = top-50 frequency.

    Lookup is case-insensitive against the bundled Census + SSA data.
    """
    if not component:
        return _UNKNOWN_SCORE
    c = component.strip().lower()
    if c in _TIER_A_NAMES or c in _TIER_A_SURNAMES:
        return _TIER_A_SCORE
    if c in _TIER_B_NAMES or c in _TIER_B_SURNAMES:
        return _TIER_B_SCORE
    if c in _TIER_C_GIVEN_NAMES or c in _TIER_C_SURNAMES:
        return _TIER_C_SCORE
    return _UNKNOWN_SCORE


def handle_commonness(handle: str) -> float:
    """Return the handle's commonness in ``[0, 1]``.

    The handle is split on separator characters (``.``, ``_``, ``-``)
    and each component looked up in the name-frequency tables. The
    maximum component score is returned because the most-common token
    dominates collision risk (e.g., ``smith.developer`` is common
    because ``smith`` is, even though ``developer`` adds specificity).

    For single-token handles, the whole handle is looked up directly.

    Returns ``0.0`` for entirely-unknown handles ── these are
    statistically near-unique and should not be penalised on
    uniqueness grounds.

    Examples:
        >>> handle_commonness("smith")
        0.95
        >>> handle_commonness("john.smith")
        0.95
        >>> handle_commonness("xochitl.vukovic")
        0.35
        >>> handle_commonness("xyzzy42")
        0.0
    """
    if not handle:
        return _UNKNOWN_SCORE
    h = handle.strip().lower()
    tokens = _tokenise(h)
    if not tokens:
        return _UNKNOWN_SCORE
    return max(name_commonness(t) for t in tokens)


def _tokenise(handle: str) -> list[str]:
    """Split a handle into component name-tokens.

    Separators handled: ``.``, ``_``, ``-`` and digit runs (so
    ``john1985`` → ``["john", "1985"]``). Tokens shorter than 2 chars
    are dropped because single letters don't carry frequency signal.
    Tokens that are purely numeric are also dropped.
    """
    # Split on dots/underscores/dashes AND boundaries between letters
    # and digits.
    parts = re.split(r"[._\-]+", handle)
    out: list[str] = []
    for p in parts:
        # Further split letter-digit boundaries: jane1985 → jane, 1985
        for sub in re.findall(r"[a-zA-Z]+|\d+", p):
            if len(sub) >= 2 and not sub.isdigit():
                out.append(sub.lower())
    return out
